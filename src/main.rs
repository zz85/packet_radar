use pcap::{Device,Capture};
use pnet::packet::{*};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use std::net::IpAddr;
use dns_lookup::{lookup_addr};
use pnet::packet::udp::UdpPacket;

use std::thread;
use websocket::sync::{Server, Client};
use websocket::message::OwnedMessage;
use std::net::TcpStream;
use serde_json::json;

struct PacketInfo {
	host: String,
}

fn main() {
	let server = Server::bind("127.0.0.1:3012").unwrap();

	for connection in server.filter_map(Result::ok) {
		thread::spawn(move || {
			let client = connection.accept().unwrap();
			cap(&client);
		});
	}
}

fn cap(client:&Client<TcpStream>) {
	println!("Hello pcap!");
	println!("Device {:?}", Device::list());

	let device = Device::lookup().unwrap();
	println!("Device {:?}", device);
	let name = device.name.as_str();
	// name can be any 

	let mut cap = Capture::from_device(name).unwrap()
			.timeout(1000)
			.promisc(true)
			.snaplen(5000)
			.open()
			// .filter("udp")
			.unwrap();

	loop {
		/*
received packet! Packet { header: PacketHeader { ts: 1562763186.719098, caplen: 68, len: 68 }, data: [240, 24, 152, 81, 58, 182, 136, 180, 166, 253, 120, 173, 8, 6, 0, 1, 8, 0, 6, 4, 0, 2, 136, 180, 166, 253, 120, 173, 192, 168, 0, 1, 240, 24, 152, 81, 58, 182, 192, 168, 0, 10, 141, 86, 156, 176, 167, 123, 211, 21, 108, 186, 149, 145, 4, 12, 18, 24, 96, 48, 157, 6, 35, 142, 166, 13, 119, 241] }
received packet! Packet { header: PacketHeader { ts: 1562763187.589954, caplen: 74, len: 74 }, data: [136, 180, 166, 253, 120, 173, 240, 24, 152, 81, 58, 182, 134, 221, 96, 15, 52, 97, 0, 20, 6, 64, 38, 1, 6, 2, 145, 0, 33, 48, 101, 137, 205, 57, 96, 24, 64, 105, 32, 1, 4, 112, 0, 1, 3, 168, 0, 0, 0, 0, 0, 0, 2, 2, 201, 247, 1, 187, 124, 242, 185, 160, 167, 39, 249, 74, 80, 16, 8, 0, 41, 136, 0, 0] }
received packet! Packet { header: PacketHeader { ts: 1562763187.622255, caplen: 94, len: 94 }, data: [240, 24, 152, 81, 58, 182, 136, 180, 166, 253, 120, 173, 134, 221, 98, 15, 43, 167, 0, 32, 6, 55, 32, 1, 4, 112, 0, 1, 3, 168, 0, 0, 0, 0, 0, 0, 2, 2, 38, 1, 6, 2, 145, 0, 33, 48, 101, 137, 205, 57, 96, 24, 64, 105, 1, 187, 201, 247, 167, 39, 249, 74, 124, 242, 185, 161, 128, 16, 0, 67, 17, 137, 0, 0, 1, 1, 8, 10, 227, 254, 150, 245, 52, 180, 54, 251, 48, 83, 14, 83, 35, 34, 21, 144] }
		*/

		match cap.next() {
			Ok(packet) => {
				// println!("received packet! {:?}", packet);
				let  header = packet.header;
				if header.caplen != header.len {
					println!("len {} cap len {}, len {}", packet.len(),  header.caplen, header.len);
				}

				// println!("len {} cap len {}, len {}", packet.len(),  header.caplen, header.len);
				// println!("received {:#X?}", packet.data);
				// println!("received {:?}", packet.data);

				// let p = PacketData::Borrowed(&packet);
				let ether = EthernetPacket::new(&packet).unwrap();
				// println!("received ether {:?}", ether);
				let etherType = ether.get_ethertype();
				// println!("received etherType {}", etherType);

				// ether.get_destination MAC, ether.get_source

				match etherType {
					EtherTypes::Ipv4 => {
						print!("IPV4 ");
						handle_ipv4_packet("meow", &ether, &client);
					},
					EtherTypes::Ipv6 => {
						print!("IPV6 ");
						handle_ipv6_packet("woof", &ether, &client);
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
    	// println!("Received: {}, dropped: {}, if_dropped: {}", stats.received, stats.dropped, stats.if_dropped);
	}
}

fn handle_ipv4_packet(interface_name: &str, ethernet: &EthernetPacket, client: &Client<TcpStream>) {
    let header = Ipv4Packet::new(ethernet.payload());
	// println!("payload length: {}", (*ethernet.payload()).len());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V4(header.get_source()),
            IpAddr::V4(header.get_destination()),
            header.get_next_level_protocol(),
            header.payload(),
			&client
        );
    } else {
        println!("[{}]: Malformed IPv4 Packet", interface_name);
    }
}

fn handle_ipv6_packet(interface_name: &str, ethernet: &EthernetPacket, client: &Client<TcpStream>) {
    let header = Ipv6Packet::new(ethernet.payload());
	// println!("payload length: {}", (*ethernet.payload()).len());
    if let Some(header) = header {
        handle_transport_protocol(
            interface_name,
            IpAddr::V6(header.get_source()),
            IpAddr::V6(header.get_destination()),
            header.get_next_header(),
            header.payload(),
			&client
        );
    } else {
        println!("[{}]: Malformed IPv6 Packet", interface_name);
    }
}

fn handle_udp_packet(interface_name: &str, source: IpAddr, destination: IpAddr, packet: &[u8],
	client: &Client<TcpStream>,
) {

	let (_, mut sender) = client.split().unwrap();
	// sender.send_message(&OwnedMessage::Text("hello".to_string())).unwrap();
	// sender.send_message(&OwnedMessage::Text(p.to_string())).unwrap();


	let dest_host = lookup_addr(&destination).unwrap();
    let udp = UdpPacket::new(packet);
	println!("Protocol: UDP, Source: {}, Destination: {} ({})", source, destination, dest_host);


    if let Some(udp) = udp {
		let p = json!({
			"len": udp.get_length(),
			"dest": udp.get_destination(),
			"src": udp.get_source(),
		});

        println!(
            "[{}]: UDP Packet: {}:{} > {}:{}; length: {}",
            interface_name,
            source,
            udp.get_source(),
            destination,
            udp.get_destination(),
            udp.get_length()
        );

		println!("Payload {:?}", udp.payload());

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
	client: &Client<TcpStream>,
) {
  	// let dest_host = lookup_addr(&destination).unwrap();
	// println!("Protocol: {}, Source: {}, Destination: {} ({})", protocol, source, destination, dest_host);

    match protocol {
        IpNextHeaderProtocols::Udp => {
            handle_udp_packet(interface_name, source, destination, packet, &client)
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
        _ => println!(
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
        ),
    }
}



/*
https://docs.rs/pnet/0.22.0/pnet/packet/ethernet/EtherTypes/index.html

*/