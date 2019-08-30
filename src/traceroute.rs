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
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use std::net::IpAddr;
use std::time::Duration;
use rand::random;
use pnet::util;
use std::net::Ipv4Addr;

// Sends a probe (ICMP, UDP, TCP)

pub fn test_ping() {
    let mut prober = Prober::setup().unwrap();

    for i in 0..20 {
        prober.ping_with_ttl(
            IpAddr::from(Ipv4Addr::new(1, 1, 1, 1)), i
        );
    }
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
        // https://subinsb.com/default-device-ttl-values/

        self.ping_with_ttl(addr, 64);
    }

    pub fn ping_with_ttl(&mut self,  addr:IpAddr, ttl:u8) {
        let payload_size = 3;
        let payload = vec!(1, 2, 3);
        // MTR sends 36 bytes 0 packet
        let min_size = MutableEchoRequestPacket::minimum_packet_size();
        println!("Size {}", min_size);
        let mut vec: Vec<u8> = vec![0; min_size + payload_size];
        let mut echo = MutableEchoRequestPacket::new(&mut vec) // vec[..]).unwrap();
            .unwrap();

        echo.set_identifier(random::<u16>());
        echo.set_sequence_number(random::<u16>());
        echo.set_icmp_type(IcmpTypes::EchoRequest);

        echo.set_payload(&payload);
        let check_sum = icmp_checksum(&echo);
        echo.set_checksum(check_sum);

        if let Err(e) = self.tx.set_ttl(ttl) {
            println!("Error setting ttl {:?}", e);
        }

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


pub fn handle_time_exceeded(time_exceeded_packet: TimeExceededPacket) {
    let payload = time_exceeded_packet.payload();

    // let ttl = payload[8];
    // 64-57=7

    // ttl #9 +1 
    // protocol #10 +1
    // checksum #11 +2
    // original source #13 +4
    // original dest #17 +4
    // icmp type #20 +1 (8 for echo)
    // icmp code #21 + 1
    // icmp checksum #22 +2
    // ping id #24 + 2
    // ping seqid #26 + 2
    // data (not guaranteed)

    let icmp_type = payload[20];
    println!("Icmp type {} check = 8", icmp_type);

    let ping_id = (payload[24] as u16) << 8 | (payload[25] as u16);
    let seq_id = (payload[26] as u16) << 8 | (payload[27] as u16);
    println!("ping_id {} seq_id {}", ping_id, seq_id);
}

lazy_static! {
    // pub static ref PROBER: Prober = Prober::setup().unwrap();
}
