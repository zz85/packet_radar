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

use crate::packet_capture::handle_ethernet_packet;

use super::PacketInfo;
use super::{parse_dns, reverse_lookup};

use dipstick::{stats_all, AtomicBucket, InputScope, Output, ScheduleFlush, Stream};

use super::parse_tcp_payload;
use super::{handle_echo_reply, handle_time_exceeded};

use std::convert::TryFrom;

use std::net::IpAddr;

use crossbeam::channel::Sender;

const CAPTURE_TCP: bool = true;
const DEBUG: bool = false;
const STATS: bool = true;

const PCAP: bool = false;

/* dipstick stats */
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
        Ok(_) => panic!("packetdump: unhandled channel type: {}"),
        Err(e) => panic!("packetdump: unable to create channel: {}", e),
    };

    let mut iter = ether_rx;

    // set up metrics
    let bucket = AtomicBucket::new();

    bucket.drain(Stream::to_stdout());
    bucket.flush_every(std::time::Duration::from_secs(1));

    let mut i = 0;

    let bytes = bucket.counter("bytes: ");
    let packets = bucket.marker("packets: ");

    loop {
        i += 1;
        match cap.next_packet() {
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
                handle_ethernet_packet(&ether, &tx, None);
            }
            Err(_) => {
                // println!("Error! {:?}", e);
            }
        }

        let stats = cap.stats().unwrap();

        if i % 1000 == 0 {
            println!(
                "Stats: Received: {}, Dropped: {}, if_dropped: {}",
                stats.received, stats.dropped, stats.if_dropped
            );
            bucket.stats(stats_all);
            bucket.flush_to(&Stream::to_stdout().new_scope()).unwrap();

            /*

            Stats: Received: 975, Dropped: 0, if_dropped: 0
            bytes: .count 43
            bytes: .sum 14158
            bytes: .max 1506
            bytes: .min 66
            bytes: .mean 329
            bytes: .rate 14575
            packets: .count 43
            packets: .rate 44

            */
        }
    }
}
