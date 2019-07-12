#![feature(drain_filter)]

use dns_lookup::{lookup_addr};
use pcap::{Device,Capture};
use pnet::packet::{*};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::udp::UdpPacket;
use serde_json::json;
use websocket::sync::{Server, Client};
use websocket::message::OwnedMessage;
use websocket::sender::Writer;

use std::sync::{Arc, RwLock};
use std::sync::mpsc::{self, Receiver, Sender};
use std::net::IpAddr;
use std::net::TcpStream;
use std::thread;
use std::env;


struct PacketInfo {
	host: String,
}

fn main() {
	// let mut moo = PacketInfo { host: "Moo ".to_owned()};
	// moo.host = "321".to_string();

	let bind = env::args().nth(1).unwrap_or("127.0.0.1:3012".to_owned());

	let server = Server::bind(bind).unwrap();
    let clients: Arc<RwLock<Vec<Writer<TcpStream>>>> = Default::default();

    let (tx, rx) = mpsc::channel();

    spawn_broadcast(rx, clients.clone());

    thread::spawn(move|| cap(tx));

	for connection in server.filter_map(Result::ok) {
        let clients = clients.clone();
		thread::spawn(move || {
			let ws = connection.accept().unwrap();
            let (_rx, tx) = ws.split().unwrap();

            clients.write().unwrap().push(tx);
		});
	}
}

fn spawn_broadcast(rx: Receiver<OwnedMessage>, clients: Arc<RwLock<Vec<Writer<TcpStream>>>>) {
    thread::spawn(move|| {
        for message in rx.iter() {
            clients.write().unwrap().drain_filter(|c| c.send_message(&message).is_err());
        }
    });
}

fn cap(tx: Sender<OwnedMessage>) {
	println!("Running pcap...");
	println!("Devices {:?}", Device::list());

	let device = Device::lookup().unwrap();
	println!("Lookup device {:?}", device);
	let name = device.name.as_str();
	// name can be "any"

	let mut cap = Capture::from_device(name)
		.unwrap()
		.timeout(1000)
		.promisc(true)
		.snaplen(5000)
		.open()
		// .filter("udp")
		.unwrap();

	loop {
		match cap.next() {
			Ok(packet) => {
				// println!("received packet! {:?}", packet);
				let header = packet.header;
				if header.caplen != header.len {
					println!("Warning bad packet.. len {}: caplen: {}, header len: {}", packet.len(),  header.caplen, header.len);
				}

				// .ts

				let ether = EthernetPacket::new(&packet).unwrap();
				let etherType = ether.get_ethertype();

				match etherType {
					EtherTypes::Ipv4 => {
						// print!("IPV4 ");
						handle_ipv4_packet("meow", &ether, &tx);
					},
					EtherTypes::Ipv6 => {
						// print!("IPV6 ");
						handle_ipv6_packet("woof", &ether, &tx);
					},
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
					},
				}
			},
			Err(_) => {
				// println!("Error! {:?}", e);
			}
		}

		let stats = cap.stats().unwrap();
    	// println!("Stats: Received: {}, Dropped: {}, if_dropped: {}", stats.received, stats.dropped, stats.if_dropped);
	}
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket, tx: &Sender<OwnedMessage>) {
    let header = Ipv4Packet::new(ethernet.payload());
	// println!("payload length: {}", (*ethernet.payload()).len());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
			tx
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket, tx: &Sender<OwnedMessage>) {
    let header = Ipv6Packet::new(ethernet.payload());
	// println!("payload length: {}", (*ethernet.payload()).len());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
			tx
        );
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8],
	tx: &Sender<OwnedMessage>
) {
	// tx.send(OwnedMessage::Text("hello".to_string())).unwrap();

	let dest_host = lookup_addr(&destination).unwrap();
    let udp = UdpPacket::new(packet);
	println!("Protocol: UDP, Source: {}, Destination: {} ({})", source, destination, dest_host);


    if let Some(udp) = udp {
		let p = json!({
			"len": udp.get_length(),
			"dest":
				destination,
				// format!("{}:{}", destination, udp.get_destination()),
			"src":
				source,
				// format!("{}:{}", source, udp.get_source()),
		});

		println!("{}", p.to_string());
		tx.send(OwnedMessage::Text(p.to_string())).unwrap();

        println!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );

		// start parsing 
		let payload = udp.payload();
		// payload[]


		// println!("Payload {:?}", udp.payload());

    } else {
        println!("[{}]: Malformed UDP Packet", interface_name);
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
  	// let dest_host = lookup_addr(&destination).unwrap();
	// println!("Protocol: {}, Source: {}, Destination: {} ({})", protocol, source, destination, dest_host);

    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet, tx)
        }
        IpNextHeaderProtocols::Tcp => {
            // handle_tcp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmp => {
            // handle_icmp_packet(interface_name, source, destination, packet)
        }
        IpNextHeaderProtocols::Icmpv6 => {
            // handle_icmpv6_packet(interface_name, source, destination, packet)
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
		},
    }
}