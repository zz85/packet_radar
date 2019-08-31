use pnet::packet::ip::IpNextHeaderProtocols;
// use pnet::packet::udp::MutableUdpPacket;
use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::{MutablePacket, Packet};
use pnet::transport::transport_channel;
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::TransportSender;
use pnet::util;
use pnet_macros_support::types::u16be;
use rand::random;
use std::fmt;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use std::collections::HashMap;
use std::sync::RwLock;

lazy_static! {
    // pub static ref PROBER: Prober = Prober::setup().unwrap();

    // maps ping id and seq id back to the original probe request
    static ref OUTGOING_PROBES: RwLock<HashMap<String, Probe>> = Default::default();

    // traceroute requests, lookup traceroute info by original search dest
    static ref TRACEROUTES: RwLock<HashMap<String, Traceroute>> = Default::default();

    // map all addresses - look up individual nodes, gather ttl, avg loss, rtt
}

struct Traceroute {
    destination: String,
    probes: Vec<ProbeResult>, // list of probes
                              // TODO map to result? <hop, Info<exceeded, unreachable, reply> + ip>
}

impl Traceroute {
    fn new(dest: String) -> Traceroute {
        Traceroute {
            destination: dest,
            probes: Vec::new(),
        }
    }
}

// Probe Request
struct Probe {
    ping_id: u16,
    sequence_id: u16,
    ttl: u8,
    destination: String,
    sent_time: Instant,
}

impl Probe {
    fn new(dest: String, ttl: u8) -> Probe {
        Probe {
            ping_id: random::<u16>(),
            sequence_id: random::<u16>(),
            ttl: ttl,
            destination: dest,
            sent_time: Instant::now(),
        }
    }

    fn format_key(ping_id: u16, sequence_id: u16) -> String {
        format!("{}:{}", ping_id, sequence_id)
    }

    fn outgoing_key(&self) -> String {
        Probe::format_key(self.ping_id, self.sequence_id)
    }
}

impl fmt::Display for Probe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Probe ({}, {}, {}, {}, {:?})",
            self.ping_id, self.sequence_id, self.ttl, self.destination, self.sent_time
        )
    }
}

#[derive(Debug)]
enum ProbeResult {
    Pending {}, // to be sent
    Idle {
        addr: IpAddr,
    }, // waiting for response
    Receive {
        addr: IpAddr,
        rtt: Duration,
        hop: u8,
    }, // have a result
}

impl ProbeResult {
    // fn is_receive(&self) -> bool {
    //     match *self {
    //         Receive => true,
    //         _ => false,
    //     }
    // }

    fn get_hop(&self) -> u8 {
        match *self {
            ProbeResult::Receive { hop, .. } => hop,
            _ => std::u8::MAX,
        }
    }
}

// Sends a probe (ICMP, UDP, TCP)
pub fn test_ping() {
    let mut prober = Prober::setup().unwrap();

    prober.ping(IpAddr::from(Ipv4Addr::new(1, 1, 1, 1)));

    test_traceroute();
}

pub fn test_traceroute() {
    let mut prober = Prober::setup().unwrap();

    let addr = IpAddr::from(Ipv4Addr::new(1, 1, 1, 1));
    let dest = addr.to_string();

    let traceroute = Traceroute::new(dest);

    TRACEROUTES
        .write()
        .unwrap()
        .insert(traceroute.destination.clone(), traceroute);

    for i in 0..20 {
        prober.ping_with_ttl(addr, i);
    }
}

pub fn probe_udp(dest: &str) {}

pub fn probe_udp_dest_with_ttl() {}

// unique hosts -> hops

fn icmp_checksum(packet: &MutableEchoRequestPacket) -> u16be {
    util::checksum(packet.packet(), 1)
}

pub struct Prober {
    tx: TransportSender,
}

/**
 * TODO: add a timer for every interval (eg. 250ms)
 * the loop does
 *    1. gather probe results (echo reponse, ttl, destination unreachable)
 *    2. remove idle probes (sent probes without responses)
 *    3. send pending probes
 */

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

    pub fn ping(&mut self, addr: IpAddr) {
        // https://subinsb.com/default-device-ttl-values/

        self.ping_with_ttl(addr, 64);
    }

    pub fn ping_with_ttl(&mut self, addr: IpAddr, ttl: u8) {
        let dest = addr.to_string();
        // register probe
        let probe = Probe::new(dest, ttl);

        let payload_size = 3;
        let payload = vec![1, 2, 3];
        // MTR sends 36 bytes 0 packet
        let min_size = MutableEchoRequestPacket::minimum_packet_size();
        println!("Size {}", min_size);
        let mut vec: Vec<u8> = vec![0; min_size + payload_size];
        let mut echo = MutableEchoRequestPacket::new(&mut vec) // vec[..]).unwrap();
            .unwrap();

        echo.set_identifier(probe.ping_id);
        echo.set_sequence_number(probe.sequence_id);
        echo.set_icmp_type(IcmpTypes::EchoRequest);

        echo.set_payload(&payload);
        let check_sum = icmp_checksum(&echo);
        echo.set_checksum(check_sum);

        if let Err(e) = self.tx.set_ttl(ttl) {
            println!("Error setting ttl {:?}", e);
        }

        OUTGOING_PROBES
            .write()
            .unwrap()
            .insert(probe.outgoing_key(), probe);
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

pub fn handle_time_exceeded(source: IpAddr, time_exceeded_packet: TimeExceededPacket) {
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

    if icmp_type != 8 {
        println!("WARNING, icmp type check failed {}", icmp_type);
    }

    let ping_id = (payload[24] as u16) << 8 | (payload[25] as u16);
    let seq_id = (payload[26] as u16) << 8 | (payload[27] as u16);

    println!("ping_id {} seq_id {}", ping_id, seq_id);

    handle_ping_id(source, ping_id, seq_id);
}

pub fn handle_echo_reply(source: IpAddr, echo_reply: EchoReplyPacket) {
    handle_ping_id(
        source,
        echo_reply.get_identifier(),
        echo_reply.get_sequence_number(),
    );
}

fn handle_ping_id(source: IpAddr, ping_id: u16, seq_id: u16) {
    let key = Probe::format_key(ping_id, seq_id);

    if let Some(probe) = OUTGOING_PROBES.write().unwrap().remove(&key) {
        println!(
            "Matches probe with ttl {} for dest {}, {}",
            probe.ttl, probe.destination, source
        );

        // add results
        TRACEROUTES
            .write()
            .unwrap()
            .get_mut(&probe.destination)
            .map(|trace| {
                trace.probes.push(ProbeResult::Receive {
                    addr: source,
                    rtt: Instant::now().duration_since(probe.sent_time),
                    hop: probe.ttl,
                });

                /*
                let results = trace.probes
                    .iter()
                    .filter(|s| s.is_receive())
                    .sort_by(|a, b|  b.hop.cmp(&a.hop));

                for (i, pair) in results.enumerate() {
                    println!("{}: {:?}", i, pair);
                }*/

                trace.probes.sort_by(|a, b| a.get_hop().cmp(&b.get_hop()));

                for (i, pair) in trace.probes.iter().enumerate() {
                    println!("{}: {:?}", i, pair);
                }
            });
    }
}
