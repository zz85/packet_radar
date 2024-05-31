use crossbeam::Receiver;
use lazy_static::lazy_static;
use libproc::libproc::proc_pid;
use std::{cmp, net::IpAddr, sync::Arc};

use crate::socket::{get_processes, SockInfo, SockType};
use hdrhistogram::Histogram;
use pretty_bytes::converter::convert;

lazy_static! {
    pub static ref CONNECTIONS: Arc<RwLock<ConnectionTracker>> = Default::default();
}

/*

The best way to get process info with packets is to receive
the process id together with a packet capture.

On Linux, you could receive the pid by using a ebpf filter.
On macs, using the pseudo pktap interface provides pid info,
which is how the apple's tcpdump -k option works.
https://github.com/apple-opensource-mirror/tcpdump/blob/102bd58d37bdecfe92f534b0f01392f04789303b/tcpdump/tcpdump.c#L2071

This isn't the typical case tho. So one way would be to figure how
to interface with pktap directly or parse the output of tcpdump -knn.

Otherwise, most network tools provides you with network captures or
process informations separatey. To join them you typically then have
to look up /proc/ or look up networking tools with process information
(netstat -nlp, lsof, ss). Note all of these would require sudo to
run. In our current implementation, we use existing capture methods
(/dev/bpf pnet datalink or libpcap) then create a map and looking up lsof.

5 tuple (udp, sip, sp, dip, dp) -> to processes

on new connection, look up
a) /proc/net/ (linux)
b) lsof (mac) - requires spawnning processes
   lsof internals - https://github.com/apple-opensource/lsof/blob/master/lsof/
c) netstat (pipe) or netstat2 (bindings)
d) bpf filter (eg. tcpdump -k)

also see https://github.com/dalance/procs - https://github.com/dalance/procs/pull/9/files - https://github.com/dalance/procs/commit/e99a21b55121b3b99a6edc64a94ade1334bb7dee https://github.com/dalance/procs/blob/cfecc8ed37e5d34fc4f59401cd87f14b243250c7/src/process/macos.rs
https://opensource.apple.com/source/lsof/lsof-49/lsof/dialects/darwin/libproc/dsock.c
https://github.com/sveinbjornt/Sloth
https://opensource.apple.com/source/xnu/xnu-1504.15.3/bsd/sys/proc_info.h.auto.html

psutil/rsof
libutils2
https://crates.io/crates/procfs
https://github.com/andrewdavidmackenzie/libproc-rs

MacOS
sudo lsof -iTCP -sTCP:LISTEN -P -n
sudo lsof -iUDP -P -n
sudo lsof -i
netstat -anl
*/

/* proc pid: proc_listpids, proc_name, proc_pidinfo, proc_regionfilename, proc_pidpath */

fn unique_tuple(tuple: (String, u16, String, u16)) -> (String, u16, String, u16) {
    let (a1, p1, a2, p2) = tuple;

    match a1.cmp(&a2) {
        cmp::Ordering::Less => (a1, p1, a2, p2),
        _ => (a2, p2, a1, p1),
    }
}

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;
use std::thread;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Default)]
struct ProcessMeta {
    pid: u32,
    name: String,
    process_path: String,
    bytes: u64,
    bytes_recv: u64,
    bytes_sent: u64,
}

use crate::packet_capture::is_local;
use crate::structs::{PacketInfo, PacketType};

#[derive(Debug, Clone)]
struct Meter {
    histo: Histogram<u64>,
    rate: Histogram<u64>,
    last_tick: Instant,
    accum: u64,
    current: u64,
}

impl Meter {
    fn add(&mut self, value: u64) {
        self.histo += value;
        self.accum += value;
        self.current += value;

        if self.last_tick.elapsed() >= Duration::from_millis(1000) {
            println!("Bytes {}", self.current);
            self.rate += self.current;
            self.current = 0;

            self.last_tick = Instant::now();
        }
    }

    fn stats(&self) {
        println!(
            "Stats Count: {} Min: {} P50: {} P95: {}, Max: {}",
            self.histo.len(),
            self.histo.min(),
            self.histo.value_at_quantile(0.5),
            self.histo.value_at_quantile(0.95),
            self.histo.max(),
        );

        println!(
            "Bytes per second Min: {} P50: {} P95: {}, Max: {}",
            self.rate.value_at_quantile(0.),
            self.rate.value_at_quantile(0.5),
            self.rate.value_at_quantile(0.95),
            self.rate.value_at_quantile(1.),
        );
    }
}

impl Default for Meter {
    fn default() -> Self {
        Self {
            histo: Histogram::<u64>::new(3).unwrap(),
            rate: Histogram::<u64>::new(3).unwrap(),
            last_tick: Instant::now(),
            accum: 0,
            current: 0,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConnectionTracker {
    /// connections populated by packet info events
    connections: HashMap<(String, u16, String, u16), ConnectionMeta>,
    /// cached pids -> process meta infomation
    pid_cache: HashMap<u32, ProcessMeta>,

    out_bytes: Meter,
    in_bytes: Meter,
}

impl ConnectionTracker {
    /// handles packet info event to build state of connections
    fn add_packet(&mut self, msg: PacketInfo) {
        let src = msg.src.parse::<IpAddr>().unwrap();
        let dst = msg.dest.parse::<IpAddr>().unwrap();
        let src_port = msg.src_port;
        let dst_port = msg.dest_port;
        let pid = msg.pid;

        if let Some(pid) = pid {
            let meta = self.update_pid_cache(pid);
            println!("{meta:?}");
        }

        let proto = match msg.t {
            PacketType::Tcp => SockType::TCP,
            PacketType::Udp => SockType::UDP,
        };

        let keyed_tuple = unique_tuple((msg.src, msg.src_port, msg.dest, msg.dest_port));

        // Populate connections
        let conn_meta = self.connections.entry(keyed_tuple).or_insert_with(|| {
            let info = match is_local(&src) {
                true => SockInfo {
                    proto,
                    local_addr: src,
                    local_port: src_port,
                    remote_addr: dst,
                    remote_port: dst_port,
                    pid,
                    state: None,
                },
                false => SockInfo {
                    proto,
                    local_addr: dst,
                    local_port: dst_port,
                    remote_addr: src,
                    remote_port: src_port,
                    pid,
                    state: None,
                },
            };
            ConnectionMeta::new_with_sock_info(info)
        });

        // update connections tuples with bytes sent
        let msg_len = msg.len as u64;
        let mut bytes_sent = 0;
        let mut bytes_recv: u64 = 0;
        if conn_meta.info.local_addr == src {
            bytes_sent = msg_len;
            self.out_bytes.add(bytes_sent);
        } else {
            bytes_recv = msg_len;
            self.in_bytes.add(bytes_recv);
        }

        conn_meta.bytes_sent += bytes_sent;
        conn_meta.bytes_recv += bytes_recv;

        if let Some(pid) = conn_meta.info.pid {
            self.pid_cache.entry(pid).and_modify(|pid| {
                pid.bytes += msg_len;
                pid.bytes_sent += bytes_sent;
                pid.bytes_recv += bytes_recv;
            });
        }
    }

    /// display top candidates based on bandwidth
    fn top(&self) {
        // Breakdown top talkers
        // 1. by connections (using 5 tuples)
        // 2. by pid (unique process)
        // TODO
        // 3. by remote destination (based on ip or domain or preferred name eg. sni)
        // 4. by process names
        // 5. asns
        // 6. countries

        let mut connections: Vec<ConnectionMeta> = self.connections.values().cloned().collect();

        connections.sort_by(|a, b| b.bytes_recv.cmp(&a.bytes_recv));

        println!("Top connections ({})", connections.len());
        println!("----------");
        connections[..50.min(connections.len())]
            .into_iter()
            .for_each(|v| {
                println!(
                    "[{}] {:?} {}:{} - {}/{}",
                    v.info.pid.unwrap_or(0),
                    v.info.proto,
                    v.info.remote_addr,
                    v.info.remote_port,
                    v.bytes_recv,
                    v.bytes_sent,
                )

                // println!("{:?}", v)
            });
        println!("----------");

        let mut top_pids: Vec<ProcessMeta> = self.pid_cache.values().cloned().collect();
        top_pids.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        println!("Top PID ({})", top_pids.len());
        println!("----------");
        top_pids[..20.min(top_pids.len())]
            .into_iter()
            .for_each(|v| {
                println!(
                    "[{}] {} - {}/{} | {}",
                    v.pid,
                    v.name,
                    v.bytes_recv,
                    v.bytes_sent,
                    convert(v.bytes as f64)
                )

                // println!("{:?}", v)
            });
        println!("----------");

        #[derive(Default, Debug)]
        struct ProcStats {
            rtt: Duration,
            connections: u32,
            pids: HashSet<u32>,
            ja4: HashSet<String>,
            sni: HashSet<String>,
        }
        let mut process_fingerprint: HashMap<&str, ProcStats> = Default::default();

        // reference TCP stats
        let conns_meta = crate::tcp::TCP_STATS.clone();

        self.connections
            .iter()
            .for_each(|((src, sport, dst, dport), meta)| {
                let key = match is_local(&meta.info.local_addr) {
                    true => format!("tcp_{src}:{sport}_{dst}:{dport}"),
                    false => format!("tcp_{dst}:{dport}_{src}:{sport}"),
                };

                let pid_info = meta.info.pid.and_then(|pid| self.pid_cache.get(&pid));

                match (pid_info, conns_meta.conn_map.get(&key)) {
                    (Some(pid_info), Some(conn)) => {
                        let proc_stats = process_fingerprint
                            .entry(pid_info.name.as_str())
                            .or_default();

                        if let Some(ja4) = &conn.ja4 {
                            proc_stats.ja4.insert(ja4.clone());
                        }

                        if let Some(sni) = &conn.sni {
                            proc_stats.sni.insert(sni.clone());
                        }

                        let diff = conn.server_time.duration_since(conn.client_time);
                        if diff.as_millis() > 0 {
                            proc_stats.rtt = diff;
                        }

                        proc_stats.pids.insert(pid_info.pid);
                        proc_stats.connections += 1;
                    }
                    _ => {}
                }
            });

        // Fingerprints: {"com.apple.WebKit.Networking": {"t13d2014h2_a09f3c656075_14788d8d241b", "", "t13d2014h1_a09f3c656075_14788d8d241b"}, "wget": {"t13d691100_8b2139ff7677_4a0154eed145"}, "firefox": {"t13d1715h2_5b57614c22b0_7121afd63204", "t13d1715h1_5b57614c22b0_7121afd63204", "t00d1410h2_c866b44c5a26_b5b8faed2b99"}, "Microsoft Update Assistant": {"t13d1314h2_f57a46bbacb6_14788d8d241b"}, "Microsoft PowerPoint": {"t13d2014h2_a09f3c656075_14788d8d241b"}, "Google Chrome Helper": {"t13d1517h2_8daaf6152771_b0da82dd1658", "", "t13d1516h2_8daaf6152771_02713d6af862"}, "curl": {"t13d1812h2_e8a523a41297_3d739a8c35e1"}, "Slack Helper": {"t13d1517h2_8daaf6152771_b0da82dd1658"}, "Safari": {"t13d2014h2_a09f3c656075_14788d8d241b"}, "itunescloudd": {"t13d2014h2_a09f3c656075_14788d8d241b"}, "parsecd": {"t13d2015h2_a09f3c656075_3d00e4afe3b1"}}
        println!("Fingerprints: {process_fingerprint:?}");

        // TODO augument via mac's PKTAP
        // sudo tcpdump -i en0,pktap -w - | tee moo.pcapng
        // or parse via https://github.com/rusticata/pcap-parser/pulls
        println!("----------");

        println!("Out");
        self.out_bytes.stats();
        println!("In");
        self.in_bytes.stats();

        println!("----------");
    }

    // fetch and insert into cache
    fn update_pid_cache(&mut self, pid: u32) -> &ProcessMeta {
        // update pid cache
        self.pid_cache.entry(pid).or_insert_with(|| {
            let process_path = match proc_pid::pidpath(pid as i32) {
                Ok(name) => name,
                Err(_) => " - ".to_owned(),
            };

            let name = match proc_pid::name(pid as i32) {
                Ok(name) => name,
                // for root processes, name may not be found but process path might
                Err(_) => process_path
                    .split('/')
                    .into_iter()
                    .last()
                    .map(|v| v.to_owned())
                    .unwrap_or_default(),
            };

            let meta = ProcessMeta {
                pid,
                name,
                process_path,
                ..Default::default()
            };

            meta
        });

        self.pid_cache.get(&pid).unwrap()
    }

    /// get pids and process informations for all sockets
    fn update_pid_info(&mut self) {
        let sockets = get_processes_and_sockets();

        // sockets.iter().for_each(|v| println!("{}", v));
        // println!("Sockets {}", sockets.len());

        sockets.into_iter().for_each(|sock| {
            let pid = sock.pid.unwrap();

            self.update_pid_cache(pid);

            // if 4 tuple is found, update pid information
            self.connections
                .entry(unique_tuple(sock.four_tuple()))
                .and_modify(|c| {
                    c.info.pid = sock.pid;
                    c.info.state = sock.state;
                })
                .or_insert(ConnectionMeta::new_with_sock_info(sock));
        });
    }
}

#[derive(Debug, Clone)]
struct ConnectionMeta {
    bytes_sent: u64,
    bytes_recv: u64,
    info: SockInfo,
    // packet count
    // current window -> speed
}

impl ConnectionMeta {
    fn new_with_sock_info(info: SockInfo) -> Self {
        ConnectionMeta {
            bytes_sent: 0,
            bytes_recv: 0,
            info,
        }
    }
}

pub fn start_monitoring(rx: Receiver<PacketInfo>) {
    // TODO move these into a single protected struct and avoid unwraps!
    // let connections: Arc<RwLock<ConnectionTracker>> = Default::default();

    let connections_on_packet = CONNECTIONS.clone();

    // Update connection tracker based on packets received
    thread::spawn(move || {
        let connections = connections_on_packet;
        for msg in rx.iter() {
            // println!("Got {:?}", msg);
            connections.write().unwrap().add_packet(msg);
        }
    });

    // let tracker = connections.clone();
    // thread::spawn(move || loop {
    //     tracker.write().unwrap().update_pid_info();
    //     tracker.read().unwrap().top();

    //     thread::sleep(Duration::from_millis(3000));
    // });

    let connections_for_pids = CONNECTIONS.clone();
    thread::spawn(move || loop {
        connections_for_pids.write().unwrap().update_pid_info();
        thread::sleep(Duration::from_millis(1000));
    });

    let top_processes = CONNECTIONS.clone();
    thread::spawn(move || loop {
        top_processes.read().unwrap().top();

        thread::sleep(Duration::from_millis(5000));
    });
}

// Get sockets
pub fn get_processes_and_sockets() -> Vec<SockInfo> {
    let socks = get_processes().unwrap_or_default();
    socks
}

#[test]
fn test() {
    use crate::test_netstat2::{get_sys, test_netstat2};
    use std::time::Instant;

    // Test experimentation
    println!("Native MacOS network descriptions");
    println!("===============");
    let start = Instant::now();
    // probably as good as lsof -P -i4 -i6 -c 0
    get_processes_and_sockets();
    println!("\n\n # Netstat1 {:?}", start.elapsed());

    println!("Test netstat 2");
    println!("===============");
    let start = Instant::now();
    test_netstat2();
    println!("\n\n # Netstat2 {:?}", start.elapsed());

    /* track connection, lookup connections to pid, count pid ++ */
}
