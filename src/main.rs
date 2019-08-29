#![feature(drain_filter)]

use pcap::{Capture, Device};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::{echo_reply, echo_request, time_exceeded, IcmpPacket, IcmpTypes};
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;

use pnet::packet::*;

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::convert::TryFrom;

use websocket::message::OwnedMessage;
use websocket::sender::Writer;
use websocket::sync::Server;

use std::env;
use std::net::IpAddr;
use std::net::TcpStream;
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, RwLock};
use std::thread;

#[macro_use]
extern crate lazy_static;

mod dns;
use dns::{parse_dns, reverse_lookup};

mod tcp;
use tcp::parse_tcp_payload;

mod traceroute;

const CAPTURE_TCP: bool = true;
const DEBUG: bool = false;
const STATS: bool = false;

use dipstick::{stats_all, AtomicBucket, InputScope, Output, ScheduleFlush, Stream};
use std::io;

#[derive(Serialize, Deserialize, Debug)]
struct PacketInfo {
    len: u16,
    src: String,
    dest: String,
    src_port: u16,
    dest_port: u16,
    t: String, // type: t for tcp, u for udp
               // todo timestamp + id
}

#[derive(Serialize, Deserialize, Debug)]
struct ClientRequest {
    req: String,
    #[serde(default = "default_type")]
    r#type: String,
    value: String,
}

fn default_type() -> String {
    "".to_string()
}

/**
 * This file starts a packet capture and a websocket server
 * Events are forwarded to connected clients
 */

fn main() {
    let bind = env::args().nth(1).unwrap_or("127.0.0.1:3012".to_owned());

    println!(
        "Websocket server listening on {}. Open html/packet_viz.html",
        bind
    );
    let server = Server::bind(bind).unwrap();

    let clients: Arc<RwLock<Vec<Writer<TcpStream>>>> = Default::default();

    let (tx, rx) = mpsc::channel();

    spawn_broadcast(rx, clients.clone());

    thread::spawn(move || cap(tx));

    for connection in server.filter_map(Result::ok) {
        let clients = clients.clone();

        thread::spawn(move || {
            let ws = connection.accept().unwrap();
            let ip = ws.peer_addr().unwrap();
            let (mut rx, mut _tx) = ws.split().unwrap();

            // add writer stream to shared vec
            clients.write().unwrap().push(_tx);

            for message in rx.incoming_messages() {
                let message = message.unwrap();

                match message {
                    OwnedMessage::Close(_) => {
                        // let message = OwnedMessage::Close(None);
                        // tx.send_message(&message).unwrap();
                        println!("Client {} disconnected", ip);
                        return;
                    }
                    OwnedMessage::Text(text) => {
                        // json parse request here
                        let data: ClientRequest = serde_json::from_str(&text).unwrap();

                        let req = data.req;
                        // println!("data req: {}, val: {}", req, data.value);

                        match req.as_ref() {
                            "lookup" => {
                                // handle look up address
                                let ip = data.value;
                                let hostname = reverse_lookup(ip.clone());
                                // println!("Name look up from: {} to {}", destination, hostname);

                                let p = json!({
                                    "type": "lookup_addr",
                                    "ip": ip,
                                    "hostname": hostname,
                                })
                                .to_string();

                                let message = OwnedMessage::Text(p);
                                clients
                                    .write()
                                    .unwrap()
                                    .drain_filter(|c| c.send_message(&message).is_err());
                            }
                            "local_addr" => {
                                let interfaces = pnet::datalink::interfaces();
                                for interface in interfaces {
                                    // println!("Interface {:?}", interface.ips);

                                    for ip in interface.ips {
                                        let src = ip.ip();

                                        let p = json!({
                                            "type": "local_addr",
                                            "ip": src,
                                        })
                                        .to_string();

                                        let message = OwnedMessage::Text(p);
                                        clients
                                            .write()
                                            .unwrap()
                                            .drain_filter(|c| c.send_message(&message).is_err());
                                    }
                                }
                            }
                            _ => {}
                        }

                        // handle filtering
                        // handle get buffers
                    }
                    OwnedMessage::Binary(buf) => {}
                    others => {
                        println!("ok {:?}", others);
                    }
                }
            }
        });
    }
}

fn spawn_broadcast(rx: Receiver<OwnedMessage>, clients: Arc<RwLock<Vec<Writer<TcpStream>>>>) {
    thread::spawn(move || {
        for message in rx.iter() {
            clients
                .write()
                .unwrap()
                .drain_filter(|c| c.send_message(&message).is_err());
        }
    });
}

fn cap(tx: Sender<OwnedMessage>) {
    println!("Running pcap...");
    println!("Devices {:?}", Device::list());

    let device = Device::lookup().unwrap();
    println!("Default device {:?}", device);

    let name = device.name.as_str();
    // "any";
    // "lo0";

    println!("Capturing on device {:?}", name);

    let mut cap = Capture::from_device(name)
        .unwrap()
        .timeout(1000)
        .promisc(true)
        // .snaplen(5000)
        .open()
        .unwrap();

    // does a bpf filter
    // cap.filter(&"udp").unwrap();

    // set up metrics
    let bucket = AtomicBucket::new();

    if STATS {
        bucket.drain(Stream::to_stdout());
        bucket.flush_every(std::time::Duration::from_secs(1));
    }

    let mut i = 0;

    let bytes = bucket.counter("bytes: ");
    let packets = bucket.marker("packets: ");

    traceroute::test_ping();

    loop {
        i += 1;
        match cap.next() {
            Ok(packet) => {
                bytes.count(packet.len());
                packets.mark();
                // println!("received packet! {:?}", packet);
                let header = packet.header;
                if header.caplen != header.len {
                    println!(
                        "Warning bad packet.. len {}: caplen: {}, header len: {}",
                        packet.len(),
                        header.caplen,
                        header.len
                    );
                }

                // .ts

                let ether = EthernetPacket::new(&packet).unwrap();
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
                        continue;
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
            Err(_) => {
                // println!("Error! {:?}", e);
            }
        }

        let stats = cap.stats().unwrap();
        if i % 10000 == 0 {
            println!(
                "Stats: Received: {}, Dropped: {}, if_dropped: {}",
                stats.received, stats.dropped, stats.if_dropped
            );
            bucket.stats(stats_all);
            bucket.flush_to(&Stream::to_stdout().new_scope()).unwrap();
        }
    }
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket, tx: &Sender<OwnedMessage>) {
    let header = Ipv4Packet::new(ethernet.payload());
    if let Some(header) = header {
        println!("TTL {}", header.get_ttl());

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

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket, tx: &Sender<OwnedMessage>) {
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
    tx: &Sender<OwnedMessage>,
) {
    let udp = UdpPacket::new(packet);

    if let Some(udp) = udp {
        let packet_info = PacketInfo {
            len: udp.get_length(),
            dest: destination.to_string(),
            src: source.to_string(),
            dest_port: udp.get_destination(),
            src_port: udp.get_source(),
            t: String::from("u"),
        };

        let payload = serde_json::to_string(&packet_info).unwrap();
        tx.send(OwnedMessage::Text(payload)).unwrap();

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

        if udp.get_source() == 53 {
            // println!("Payload {:?}", payload);
            parse_dns(payload).map(|v| {
                // println!("DNS {}\n", v);
                v.parse_body();
            });
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
    tx: &Sender<OwnedMessage>,
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

        let packet_info = PacketInfo {
            len: u16::try_from(tcp.packet_size()).unwrap(),
            dest: destination.to_string(),
            src: source.to_string(),
            dest_port: tcp.get_destination(),
            src_port: tcp.get_source(),
            t: String::from("t"),
        };

        let payload = serde_json::to_string(&packet_info).unwrap();
        tx.send(OwnedMessage::Text(payload)).unwrap();

        // strip tcp headers
        let packet = tcp.payload();

        parse_tcp_payload(packet);
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
    tx: &Sender<OwnedMessage>,
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
        match icmp_packet.get_icmp_type() {
            IcmpTypes::EchoReply => {
                let echo_reply_packet = echo_reply::EchoReplyPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP echo reply {} -> {} (seq={:?}, id={:?})",
                    interface_name,
                    source,
                    destination,
                    echo_reply_packet.get_sequence_number(),
                    echo_reply_packet.get_identifier()
                );
            }
            IcmpTypes::EchoRequest => {
                let echo_request_packet = echo_request::EchoRequestPacket::new(packet).unwrap();
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
            IcmpTypes::TimeExceeded => {
                let time_exceeded_packet = time_exceeded::TimeExceededPacket::new(packet).unwrap();
                println!(
                    "[{}]: ICMP TimeExceeded {} -> {} (seq={:?}, payload={:?})",
                    interface_name,
                    source,
                    destination,
                    time_exceeded_packet,
                    time_exceeded_packet.payload(),
                );
            }
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
        println!(
            "[{}]: ICMPv6 packet {} -> {} (type={:?})",
            interface_name,
            source,
            destination,
            icmpv6_packet.get_icmpv6_type()
        )
    } else {
        println!("[{}]: Malformed ICMPv6 Packet", interface_name);
    }
}
