use pnet::packet::icmp::echo_reply::EchoReplyPacket;
use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::icmp::time_exceeded::TimeExceededPacket;
use pnet::packet::icmp::IcmpTypes;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
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

use serde::{Deserialize, Serialize};
use serde_json;

use crossbeam::channel::Sender;
use websocket::message::OwnedMessage;

use std::collections::HashMap;
use std::sync::RwLock;

lazy_static! {
    pub static ref PROBER: RwLock<Prober> = Default::default();
}

pub struct Prober {
    // maps ping id and seq id to the original probe request
    outgoing_probes: HashMap<String, Probe>,

    // traceroute requests, lookup traceroute info by original search dest
    trace_routes: HashMap<IpAddr, Traceroute>,

    // map all addresses - look up individual nodes, gather ttl, avg loss, rtt
    prober: Option<IcmpProber>, // transport implementation

    // callback: Box<FnMut()>,
    tx: Option<Sender<OwnedMessage>>,
}

impl Default for Prober {
    fn default() -> Prober {
        Prober::new()
    }
}

impl Prober {
    pub fn new() -> Prober {
        Prober {
            outgoing_probes: Default::default(),
            trace_routes: Default::default(),
            prober: IcmpProber::setup(),
            tx: None,
        }
    }

    pub fn set_callback(&mut self, tx: Sender<OwnedMessage>) {
        self.tx = Some(tx);
    }

    pub fn ping(&mut self, addr: IpAddr) {
        self.probe_with_ttl(addr, 64);
    }

    pub fn traceroute(&mut self, addr: IpAddr) {
        let traceroute = Traceroute::new(addr);

        self.trace_routes
            .insert(traceroute.destination.clone(), traceroute);

        for i in 0..20 {
            self.probe_with_ttl(addr, i);
        }
    }

    fn probe_with_ttl(&mut self, addr: IpAddr, ttl: u8) {
        // register probe
        let probe = Probe::new(addr, ttl);
        let key = probe.outgoing_key().clone();
        self.prober.as_mut().unwrap().ping_with_ttl(probe);
        self.outgoing_probes.insert(key, probe);
    }

    pub fn handle_ping_id(&mut self, source: IpAddr, ping_id: u16, seq_id: u16) {
        let key = Probe::format_key(ping_id, seq_id);

        if let Some(probe) = self.outgoing_probes.remove(&key) {
            println!(
                "Matches probe with ttl {} for dest {}, {}",
                probe.ttl, probe.addr, source
            );

            let tx: &Option<Sender<OwnedMessage>> = &self.tx;

            // add results
            self.trace_routes.get_mut(&probe.addr).map(|trace| {
                trace.receive_probe(source, probe);

                // send results over websockets
                if trace.hop_reached {
                    if let Some(tx) = tx {
                        let info = TraceRouteInfo::new(trace.probes.clone(), probe.addr);
                        let payload = serde_json::to_string(&info).unwrap();
                        tx.send(OwnedMessage::Text(payload)).unwrap();
                    }
                }
            });
        }
    }
}

/**
 * TODO: add event loop with a timer for interval (eg. 250ms)
 * the loop does
 *    1. gather probe results (echo reponse, ttl, destination unreachable)
 *    2. remove idle probes (sent probes without responses)
 *    3. send pending probes
 */

struct Traceroute {
    destination: IpAddr,
    probes: Vec<ProbeResult>, // list of probes
    // TODO map to result? <hop, Info<exceeded, unreachable, reply> + ip>
    max_hop: u8,
    hop_reached: bool,
}

impl Traceroute {
    fn new(dest: IpAddr) -> Self {
        Self {
            destination: dest,
            probes: Vec::new(),
            max_hop: std::u8::MAX,
            hop_reached: false,
        }
    }

    fn reset(&mut self) {
        self.probes = Vec::new();
        self.max_hop = std::u8::MAX;
        self.hop_reached = false;
    }

    fn receive_probe(&mut self, source: IpAddr, probe: Probe) {
        if probe.ttl > self.max_hop {
            return;
        }

        if source == self.destination {
            self.hop_reached = true;
            self.max_hop = std::cmp::min(self.max_hop, probe.ttl);
        }

        // TODO clean up big ttls
        self.probes.push(ProbeResult::Receive {
            addr: source,
            rtt: Instant::now().duration_since(probe.sent_time),
            hop: probe.ttl,
        });

        self.probes.sort_by(|a, b| a.get_hop().cmp(&b.get_hop()));
        self.print();
    }

    fn print(&self) {
        for (i, pair) in self.probes.iter().enumerate() {
            println!("{}: {:?}", i, pair);
        }
    }
}

// Probe Request
#[derive(Debug, Copy, Clone)]
struct Probe {
    ping_id: u16,
    sequence_id: u16,
    ttl: u8,
    sent_time: Instant,
    addr: IpAddr,
}

impl Probe {
    fn new(addr: IpAddr, ttl: u8) -> Probe {
        Probe {
            addr,
            ping_id: random::<u16>(),
            sequence_id: random::<u16>(),
            ttl,
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
            self.ping_id, self.sequence_id, self.ttl, self.addr, self.sent_time
        )
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct TraceRouteInfo {
    data: Vec<ProbeResult>,
    destination: IpAddr,
    r#type: String,
}

impl TraceRouteInfo {
    fn new(data: Vec<ProbeResult>, destination: IpAddr) -> Self {
        Self {
            data,
            r#type: String::from("traceroute"),
            destination,
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, Debug)]
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

/**
 *
 */

// Sends a probe (ICMP, UDP, TCP)
pub fn test_ping() {
    PROBER
        .write()
        .unwrap()
        .ping(IpAddr::from(Ipv4Addr::new(1, 1, 1, 1)));
}

pub fn test_traceroute() {
    let addr = IpAddr::from(Ipv4Addr::new(1, 1, 1, 1));

    PROBER.write().unwrap().traceroute(addr);
}

pub fn traceroute(addr: IpAddr) {
    PROBER.write().unwrap().traceroute(addr);
}

pub fn set_callback(tx: Sender<OwnedMessage>) {
    PROBER.write().unwrap().set_callback(tx);
}

pub struct IcmpProber {
    tx: TransportSender,
}

impl IcmpProber {
    pub fn setup() -> Option<IcmpProber> {
        let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Icmp));

        let (tx, rx) = transport_channel(4096, protocol)
            .map_err(|e| {
                println!("An error occurred when creating the transport channel: {e}");
                e
            })
            .ok()?;

        Some(IcmpProber { tx })
    }

    fn ping_with_ttl(&mut self, probe: Probe) {
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
        let check_sum = IcmpProber::icmp_checksum(&echo);
        echo.set_checksum(check_sum);

        if let Err(e) = self.tx.set_ttl(probe.ttl) {
            println!("Error setting ttl {:?}", e);
        }

        match self.tx.send_to(echo, probe.addr) {
            x => {
                println!("Echo sent! {:?}", x);
            }
        }
    }

    fn icmp_checksum(packet: &MutableEchoRequestPacket) -> u16be {
        util::checksum(packet.packet(), 1)
    }
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

    PROBER
        .write()
        .unwrap()
        .handle_ping_id(source, ping_id, seq_id);
}

pub fn handle_echo_reply(source: IpAddr, echo_reply: EchoReplyPacket) {
    PROBER.write().unwrap().handle_ping_id(
        source,
        echo_reply.get_identifier(),
        echo_reply.get_sequence_number(),
    );
}
