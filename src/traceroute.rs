use pnet::packet::ip::IpNextHeaderProtocols;
// use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::icmp::echo_request::{EchoRequestPacket, MutableEchoRequestPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::TransportSender;
use std::net::IpAddr;
use std::time::Duration;

// Sends a probe (ICMP, UDP, TCP)

pub fn probe_udp(dest: &str) {}

pub fn probe_udp_dest_with_ttl() {}

enum ProbeResult {
    Idle { addr: IpAddr },
    Receive { addr: IpAddr, rtt: Duration },
}

// TODO address map to result? <ip,  Info>

pub fn ping() {
    // MutableEchoRequestPacket::

    let size = MutableEchoRequestPacket::minimum_packet_size();
    let mut vec: Vec<u8> = vec![0; size];
    MutableEchoRequestPacket::new(&mut vec)
        .unwrap()
        // .set_identifier()
        // .set_sequence_number()
        // .set_payload()
        ;

    // let mut vec: Vec<u8> = vec![0; packet.packet().len()];
    // let mut new_packet = MutableUdpPacket::new(&mut vec[..]).unwrap();

    // new_packet.set_source(packet.get_destination());
    // new_packet.set_destination(packet.get_source());
}

struct Prober {
    tx: TransportSender,
}

impl Prober {
    pub fn setup() -> Option<Prober> {
        let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Test1));

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

    fn send() {}
}

lazy_static! {
    static ref PROBER: Prober = Prober::setup().unwrap();
}
