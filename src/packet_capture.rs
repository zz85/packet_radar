use pcap::{Capture, Device};
use pnet::datalink::{self, NetworkInterface};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, time_exceeded, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use lazy_static::lazy_static;

use quick_cache::unsync::Cache;
use tracing::{debug, info};

use pnet::packet::*;

use crate::args::Args;
use crate::dns::parse_dns;
use crate::structs::PacketInfo;
use crate::traceroute::{handle_echo_reply, handle_time_exceeded};

use std::net::IpAddr;
use std::sync::Mutex;

use crossbeam::channel::Sender;

use crate::quic;
use crate::structs::ProcInfo;
use crate::tcp::{is_handshake_packet, parse_tcp_payload, TCP_STATS};

const CAPTURE_TCP: bool = true;
const DEBUG: bool = false;

lazy_static! {
    pub static ref BUFFER: Mutex<Cache<String, Vec<u8>>> = Mutex::new(Cache::new(50));
}

pub fn is_local(ip: &IpAddr) -> bool {
    let interfaces = pnet::datalink::interfaces();
    for interface in interfaces {
        for ipnet in interface.ips {
            if ipnet.ip() == *ip {
                return true;
            }
        }
    }

    return false;
}

fn pnet_capture(tx: Sender<PacketInfo>, name: &str) {
    use pnet::datalink::Channel::Ethernet;

    let interface_names_match = |iface: &NetworkInterface| iface.name == name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap();

    // Create a channel to receive on
    let (_, ether_rx) = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("packetdump: unhandled channel type"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    let mut iter = ether_rx;

    // process packets
    loop {
        match iter.next() {
            Ok(packet) => {
                let ether = EthernetPacket::new(packet).unwrap();
                handle_ethernet_packet(&ether, &tx, None);
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }
}

fn pcap(tx: Sender<PacketInfo>, name: &str) {
    let mut cap = Capture::from_device(name)
        .unwrap()
        .timeout(1)
        .promisc(true)
        // .snaplen(5000)
        .open()
        .unwrap();

    match cap.next_packet() {
        Ok(packet) => {
            let header = packet.header;
            if header.caplen != header.len {
                info!(
                    "Warning bad packet.. len {}: caplen: {}, header len: {}",
                    packet.len(),
                    header.caplen,
                    header.len
                );
            }
            let ether = EthernetPacket::new(&packet).unwrap();
            handle_ethernet_packet(&ether, &tx, None);
        }
        Err(_) => {
            // info!("Error! {:?}", e);
        }
    }
}

pub fn cap(tx: Sender<PacketInfo>, args: &Args) {
    info!("Running pcap...");

    if let Ok(devices) = Device::list() {
        debug!("Devices {devices:?}");

        devices.iter().for_each(|d| info!("{}", d.name))
    }

    let device = Device::lookup().unwrap().unwrap();

    let name = args
        .interface
        .as_ref()
        .map(|m| m.as_str())
        .unwrap_or_else(|| {
            info!("Default device {:?}", device);
            device.name.as_str()
        });

    // "any";
    // "lo0";

    info!("Capturing on device {:?}", name);

    let use_pcap = false;

    if use_pcap {
        pcap(tx, name);
        return;
    }

    pnet_capture(tx, name);

    // traceroute::test_ping();
    // traceroute::test_traceroute();
}

pub(crate) fn handle_ethernet_packet(
    ether: &EthernetPacket,
    tx: &Sender<PacketInfo>,
    proc: Option<&ProcInfo>,
) {
    let ether_type = ether.get_ethertype();
    let iface = "meow";

    match ether_type {
        EtherTypes::Ipv4 => {
            // print!("IPV4 ");
            handle_ipv4_packet(iface, &ether, &tx, proc);
        }
        EtherTypes::Ipv6 => {
            // print!("IPV6 ");
            handle_ipv6_packet(iface, &ether, &tx, proc);
        }
        EtherTypes::Arp => {
            // info!("ARP");
        }
        _ => {
            debug!(
                "Unknown packet: {} > {}; ethertype: {:?}",
                ether.get_source(),
                ether.get_destination(),
                ether.get_ethertype()
            )
        }
    }
}

fn handle_ipv4_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    tx: &Sender<PacketInfo>,
    proc: Option<&ProcInfo>,
) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        // info!("TTL {}", header.get_ttl());

        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            tx,
            proc,
        );
    } else {
        info!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(
    interface_name: &str,
    ethernet: &EthernetPacket,
    tx: &Sender<PacketInfo>,
    proc: Option<&ProcInfo>,
) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            tx,
            proc,
        );
    } else {
        info!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_udp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    tx: &Sender<PacketInfo>,
    proc: Option<&ProcInfo>,
) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        let packet_info = PacketInfo {
            len: packet.len() as u16,
            dest: destination.to_string(),
            src: source.to_string(),
            dest_port: udp.get_destination(),
            src_port: udp.get_source(),
            t: crate::structs::PacketType::Udp,
            pid: proc.map(|p| p.pid),
            ..Default::default()
        };

        let ja4_packet = packet_info.clone();

        tx.send(packet_info).unwrap();

        if DEBUG {
            info!(
                "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
                interface_name,
                source,
                udp.get_source(),
                destination,
                udp.get_destination(),
                udp.get_length()
            );
        }

        // start parsing
        let payload = udp.payload();

        // intercept DNS calls
        if udp.get_source() == 53 {
            // info!("Payload {:?}", payload);
            parse_dns(payload).map(|v| {
                // info!("DNS {}\n", v);
                v.parse_body();
            });

            return;
        }

        if let Some(ch) = quic::dissect(payload) {
            let info = PacketInfo {
                ja4: ch.ja4,
                sni: Some(ch.sni),
                t: crate::structs::PacketType::Ja4,
                process: proc.and_then(|p| p.name.as_ref().map(|v| v.clone())),
                ..ja4_packet
            };

            let key = match is_local(&source) {
                true => format!(
                    "udp_{}:{}_{}:{}",
                    source,
                    udp.get_source(),
                    destination,
                    udp.get_destination()
                ),
                false => format!(
                    "udp_{}:{}_{}:{}",
                    destination,
                    udp.get_destination(),
                    source,
                    udp.get_source()
                ),
            };

            let mut tcp_state = TCP_STATS.get_or_create_conn(key);
            tcp_state.pid = info.pid.clone();
            tcp_state.process_name = info.process.clone();
            tcp_state.ja4 = info.ja4.clone();
            tcp_state.sni = info.sni.clone();

            tx.send(info).unwrap();

            debug!(
                "[{}]: QUIC Packet: {}:{} > {}:{}; length: {}",
                interface_name,
                source,
                udp.get_source(),
                destination,
                udp.get_destination(),
                udp.get_length()
            );

            // TODO observe QUIC connections
            // number of connections
            // most popular endpoints
            // bitspin RTT
            // durations of connection
            // connection migrations
        }

    // info!("UDP Payload {:?}", udp.payload());
    } else {
        info!("[{}]: Malformed UDP Packet", interface_name);
    }
}

fn handle_tcp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    tx: &Sender<PacketInfo>,
    proc: Option<&ProcInfo>,
) -> Option<()> {
    if !CAPTURE_TCP {
        return None;
    }
    let tcp = TcpPacket::new(packet);

    if tcp.is_none() {
        info!("[{}]: Malformed TCP Packet", interface_name);
    }

    let tcp = tcp?;

    if DEBUG {
        info!(
            "[{}]: TCP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination(),
            packet.len()
        );
    }

    // generate a key is uniquely id the 5 tuple
    // instead of is_local(), source < destination is
    // a hack to generate unique
    let key = match is_local(&source) {
        true => format!(
            "tcp_{}:{}_{}:{}",
            source,
            tcp.get_source(),
            destination,
            tcp.get_destination()
        ),
        false => format!(
            "tcp_{}:{}_{}:{}",
            destination,
            tcp.get_destination(),
            source,
            tcp.get_source()
        ),
    };

    // tcp.get_acknowledgement()
    // get_sequence
    // options raw

    let packet_info = PacketInfo {
        len: packet.len() as u16, // this is correct, do not use tcp.packet_size();
        dest: destination.to_string(),
        src: source.to_string(),
        dest_port: tcp.get_destination(),
        src_port: tcp.get_source(),
        t: crate::structs::PacketType::Tcp,
        pid: proc.map(|p| p.pid),
        ..Default::default()
    };

    let packet_info2 = packet_info.clone();

    // info!("tcp: {:?} {:0b} {proc:?}", packet_info, tcp.get_flags());

    tx.send(packet_info).unwrap();

    // strip tcp headers
    let packet = tcp.payload();

    let is_handshake = is_handshake_packet(packet);
    // The PSH bit is the 4th bit in the TCP flags byte
    let push_bit = (tcp.get_flags() & 0x08) != 0;

    let mut cache = BUFFER.lock().unwrap();
    let buffered = cache.get(&key).is_some();

    if !(is_handshake || buffered) {
        return Some(());
    }

    let mut buffer = cache
        .get_mut_or_insert_with(&key, || Ok::<_, std::io::Error>(Vec::new()))
        .unwrap()
        .unwrap();

    buffer.extend_from_slice(packet);

    debug!(
            "key: {key}, is_handshake: {is_handshake}, buffered: {buffered}, push_bit: {push_bit}, pkt len: {}, buffer len: {}",
            packet.len(), buffer.len()
        );

    if push_bit || buffer.len() > 64000 {
        // ready to parse
        let stats = parse_tcp_payload(&buffer, &key);
        debug!("tls handshake {stats:?}");

        drop(buffer);
        cache.remove(&key);

        if let Some(conn) = stats {
            let info = PacketInfo {
                ja4: conn.ja4,
                sni: conn.sni,
                process: proc.and_then(|p| p.name.as_ref().map(|v| v.clone())),
                t: crate::structs::PacketType::Ja4,
                ..packet_info2
            };

            let mut tcp_state = TCP_STATS.get_or_create_conn(key);
            tcp_state.pid = info.pid.clone();
            tcp_state.process_name = info.process.clone();

            tx.send(info).unwrap();
        }
    }
    Some(())
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    tx: &Sender<PacketInfo>,
    proc: Option<&ProcInfo>,
) {
    // info!(
    //     "Protocol: {}, Source: {}, Destination: {} ({})",
    //     protocol, source, destination, protocol
    // );

    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet, tx, proc)
        }
        IpNextHeaderProtocols::Tcp => {
            handle_tcp_packet(interface_name, source, destination, packet, tx, proc);
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, source, destination, packet)
        }
        _ => {
            debug!(
                "[{}]: Unknown {} packet: {} > {}; protocol: {:?} length: {}",
                interface_name,
                match source {
                    IpAddr::V4(..) => "IPv4",
                    _ => "IPv6",
                },
                source,
                destination,
                protocol,
                packet.len()
            )
        }
    }
}

fn handle_icmp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmp_packet = IcmpPacket::new(packet);
    if let Some(icmp_packet) = icmp_packet {
        let icmp_payload = icmp_packet.payload();

        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                if DEBUG {
                    info!(
                        "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                        interface_name,
                        source,
                        destination,
                        echo_reply_packet.get_sequence_number(),
                        echo_reply_packet.get_identifier()
                    );
                }

                handle_echo_reply(source, echo_reply_packet);
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
                if DEBUG {
                    info!(
                        "[{}]: ICMP echo request {} -> {} (seq={:?}, id={:?})",
                        interface_name,
                        source,
                        destination,
                        echo_request_packet.get_sequence_number(),
                        echo_request_packet.get_identifier(),
                        // echo_request_packet.payload(),
                    );
                }
            }
            IcmpTypes::TimeExceeded => {
                let time_exceeded_packet = time_exceeded::TimeExceededPacket::new(packet).unwrap();
                if DEBUG {
                    info!(
                        "[{}]: ICMP TimeExceeded {} -> {} (seq={:?}, payload={:?})\n{:?}",
                        interface_name,
                        source,
                        destination,
                        time_exceeded_packet,
                        time_exceeded_packet.payload(),
                        icmp_packet
                    );
                }

                handle_time_exceeded(source, time_exceeded_packet);
            }
            // TODO Add Destination unavailable
            _ => info!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    } else {
        info!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        if DEBUG {
            info!(
                "[{}]: ICMPv6 packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmpv6_packet.get_icmpv6_type()
            )
        }
    } else {
        info!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}
