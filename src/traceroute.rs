use pnet::packet::ip::IpNextHeaderProtocols;
// use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::TransportSender;
use pnet_macros_support::types::u16be;
use std::net::IpAddr;
use std::time::Duration;
use rand::random;
use pnet::util;
use std::net::Ipv4Addr;

// Sends a probe (ICMP, UDP, TCP)

pub fn test_ping() {
    let mut prober = Prober::setup().unwrap();
    prober.ping(
        IpAddr::from(Ipv4Addr::new(1, 1, 1, 1))
    );
}

pub fn probe_udp(dest: &str) {}

pub fn probe_udp_dest_with_ttl() {}

enum ProbeResult {
    Idle { addr: IpAddr },
    Receive { addr: IpAddr, rtt: Duration },
}

// TODO address map to result? <ip,  Info>

fn icmp_checksum(packet: &MutableEchoRequestPacket) -> u16be {
    util::checksum(packet.packet(), 1)
}

pub struct Prober {
    tx: TransportSender,
}

impl Prober {
    pub fn setup() -> Option<Prober> {
        let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

        let (mut tx, mut rx) = transport_channel(4096, protocol).unwrap();
        // let (mut tx, mut rx) = match transport_channel(4096, protocol) {
        //     Ok((tx, rx)) => (tx, rx),
        //     Err(e) => panic!(
        //         "An error occurred when creating the transport channel: {}",
        //         e
        //     ),
        // };

        Some(Prober { tx })
    }

    pub fn ping(&mut self,  addr:IpAddr) {
        let payload_size = 8;
        let min_size = MutableEchoRequestPacket::minimum_packet_size();
        println!("Size {}", min_size);
        let mut vec: Vec<u8> = vec![0; min_size + payload_size];
        let mut echo = MutableEchoRequestPacket::new(&mut vec) // vec[..]).unwrap();
            .unwrap();

        echo.set_identifier(random::<u16>());
        echo.set_sequence_number(random::<u16>());
        echo.set_icmp_type(IcmpTypes::EchoRequest);

        //  set payload
        let check_sum = icmp_checksum(&echo);
        echo.set_checksum(check_sum);

        match self.tx.send_to(echo, addr) {
            x => {
                println!("Echo sent! {:?}", x);
            }
        }

    }

    // pub fn ping(&self, destination:Ipv4) {
    //     self.tx.send
    // }
}

lazy_static! {
    // pub static ref PROBER: Prober = Prober::setup().unwrap();
}
