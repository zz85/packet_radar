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

use pnet::packet::*;

use super::PacketInfo;
use super::{parse_dns, reverse_lookup};

use super::parse_tcp_payload;
use super::{handle_echo_reply, handle_time_exceeded};

use std::convert::TryFrom;

use std::net::IpAddr;

use crossbeam::channel::Sender;

use crate::quic;

const CAPTURE_TCP: bool = true;
const DEBUG: bool = false;

pub fn is_local(ip: IpAddr) -> bool {
    let interfaces = pnet::datalink::interfaces();
    for interface in interfaces {
        for ip in interface.ips {
            return true;
        }
    }

    return false;
}

pub fn cap(tx: Sender<PacketInfo>) {
    println!("Running pcap...");
    println!("Devices {:?}", Device::list());

    let device = Device::lookup().unwrap().unwrap();
    println!("Default device {:?}", device);

    let name = device.name.as_str();
    // "any";
    // "lo0";

    println!("Capturing on device {:?}", name);

    let mut cap = Capture::from_device(name)
        .unwrap()
        .timeout(1)
        .promisc(true)
        // .snaplen(5000)
        .open()
        .unwrap();

    // does a bpf filter
    // cap.filter(&"udp").unwrap();

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
                handle_ethernet_packet(&ether, &tx);
            }
            Err(e) => panic!("packetdump: unable to receive packet: {}", e),
        }
    }

    // traceroute::test_ping();
    // traceroute::test_traceroute();
}

fn handle_ethernet_packet(ether: &EthernetPacket, tx: &Sender<PacketInfo>) {
    let ether_type = ether.get_ethertype();

    match ether_type {
        EtherTypes::Ipv4 => {
            // print!("IPV4 ");
            handle_ipv4_packet("meow", &ether, &tx);
        }
        EtherTypes::Ipv6 => {
            // print!("IPV6 ");
            handle_ipv6_packet("woof", &ether, &tx);
        }
        EtherTypes::Arp => {
            // println!("ARP");
        }
        _ => {
            // 	println!(
            // 	"Unknown packet: {} > {}; ethertype: {:?}",
            // 	ether.get_source(),
            // 	ether.get_destination(),
            // 	ether.get_ethertype()
            // )
        }
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket, tx: &Sender<PacketInfo>) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        // println!("TTL {}", header.get_ttl());

        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
            tx,
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket, tx: &Sender<PacketInfo>) {
    let header = Ipv6Packet::new(ethernet.payload());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
            tx,
        );
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_udp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    tx: &Sender<PacketInfo>,
) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        let packet_info = PacketInfo {
            len: packet.len() as u16,
            dest: destination.to_string(),
            src: source.to_string(),
            dest_port: udp.get_destination(),
            src_port: udp.get_source(),
            t: String::from("u"),
        };

        tx.send(packet_info).unwrap();

        if DEBUG {
            println!(
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
            // println!("Payload {:?}", payload);
            parse_dns(payload).map(|v| {
                // println!("DNS {}\n", v);
                v.parse_body();
            });
        }

        if quic::dissect(payload) {
            println!(
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

    // println!("UDP Payload {:?}", udp.payload());
    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
    }
}

fn handle_tcp_packet(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    packet: &[u8],
    tx: &Sender<PacketInfo>,
) {
    let tcp = TcpPacket::new(packet);
    if let Some(tcp) = tcp {
        if DEBUG {
            println!(
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
        let key = match source < destination {
            // is_local(source)
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

        // tcp.get_source()
        // tcp.get_destination()
        // tcp.get_acknowledgement()
        // get_sequence
        // options raw

        // packet_size
        let packet_info = PacketInfo {
            len: packet.len() as u16, // this is correct, do not use tcp.packet_size();
            dest: destination.to_string(),
            src: source.to_string(),
            dest_port: tcp.get_destination(),
            src_port: tcp.get_source(),
            t: String::from("t"),
        };

        tx.send(packet_info).unwrap();

        // strip tcp headers
        let packet = tcp.payload();

        parse_tcp_payload(packet, &key);
    } else {
        println!("[{}]: Malformed TCP Packet", interface_name);
    }
}

fn handle_transport_protocol(
    interface_name: &str,
    source: IpAddr,
    destination: IpAddr,
    protocol: IpNextHeaderProtocol,
    packet: &[u8],
    tx: &Sender<PacketInfo>,
) {
    // println!("Protocol: {}, Source: {}, Destination: {} ({})", protocol, source, destination, dest_host);

    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet, tx)
        }
        IpNextHeaderProtocols::Tcp => {
            if CAPTURE_TCP {
                handle_tcp_packet(interface_name, source, destination, packet, tx)
            }
        }
        IpNextHeaderProtocols::Icmp => {
            handle_icmp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            handle_icmpv6_packet(interface_name, source, destination, packet)
        }
        _ => {
            /*println!(
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
            )*/
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
                    println!(
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
                    println!(
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
                    println!(
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
            _ => println!(
                "[{}]: ICMP packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmp_packet.get_icmp_type()
            ),
        }
    } else {
        println!("[{}]: Malformed ICMP Packet", interface_name);
    }
}

fn handle_icmpv6_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8]) {
    let icmpv6_packet = Icmpv6Packet::new(packet);
    if let Some(icmpv6_packet) = icmpv6_packet {
        if DEBUG {
            println!(
                "[{}]: ICMPv6 packet {} -> {} (type={:?})",
                interface_name,
                source,
                destination,
                icmpv6_packet.get_icmpv6_type()
            )
        }
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}
