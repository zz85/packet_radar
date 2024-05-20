use crossbeam::Receiver;

use libproc::libproc::proc_pid;

use std::{cmp, net::IpAddr, sync::Arc};

use crate::socket::{get_processes, SockInfo, SockType};
use hdrhistogram::Histogram;
use pretty_bytes::converter::convert;

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

use std::collections::HashMap;
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
use crate::structs::PacketType;
use crate::PacketInfo;

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
struct ConnectionTracker {
    connections: HashMap<(String, u16, String, u16), ConnectionMeta>,
    /// cached pids -> process meta infomation
    pid_cache: HashMap<u32, ProcessMeta>,

    out_bytes: Meter,
    in_bytes: Meter,
}

impl ConnectionTracker {
    fn add_packet(&mut self, msg: PacketInfo) {
        let src = msg.src.parse::<IpAddr>().unwrap();
        let dst = msg.dest.parse::<IpAddr>().unwrap();
        let src_port = msg.src_port;
        let dst_port = msg.dest_port;

        let proto = match msg.t {
            PacketType::Tcp => SockType::TCP,
            PacketType::Udp => SockType::UDP,
        };

        let keyed_tuple = unique_tuple((msg.src, msg.src_port, msg.dest, msg.dest_port));

        // Populate connections
        let conn_meta = self.connections.entry(keyed_tuple).or_insert_with(|| {
            let info = match is_local(src) {
                true => SockInfo {
                    proto,
                    local_addr: src,
                    local_port: src_port,
                    remote_addr: dst,
                    remote_port: dst_port,
                    pid: None,
                    state: None,
                },
                false => SockInfo {
                    proto,
                    local_addr: dst,
                    local_port: dst_port,
                    remote_addr: src,
                    remote_port: src_port,
                    pid: None,
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

        println!("Out");
        self.out_bytes.stats();
        println!("In");
        self.in_bytes.stats();
    }

    /// get pids and process informations for all sockets
    fn update_pid_info(&mut self) {
        let sockets = get_processes_and_sockets();

        // sockets.iter().for_each(|v| println!("{}", v));
        // println!("Sockets {}", sockets.len());

        sockets.into_iter().for_each(|sock| {
            let pid = sock.pid.unwrap();
            // update pid cache
            self.pid_cache.entry(pid).or_insert_with(|| {
                let name = match proc_pid::name(pid as i32) {
                    Ok(name) => name,
                    Err(_) => " - ".to_owned(),
                };

                let process_path = match proc_pid::pidpath(pid as i32) {
                    Ok(name) => name,
                    Err(_) => " - ".to_owned(),
                };

                let meta = ProcessMeta {
                    pid,
                    name,
                    process_path,
                    ..Default::default()
                };

                meta
            });

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
    let connections: Arc<RwLock<ConnectionTracker>> = Default::default();
    let connections_on_packet = connections.clone();

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

    let connections_for_pids = connections.clone();
    thread::spawn(move || loop {
        connections_for_pids.write().unwrap().update_pid_info();
        thread::sleep(Duration::from_millis(1000));
    });

    let top_processes = connections.clone();
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
