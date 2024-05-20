use crossbeam::Receiver;
use libc;
use libc::{c_int, c_void, size_t};

use libproc::libproc::bsd_info::BSDInfo;
use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDInfo, ProcFDType};
use libproc::libproc::net_info::{
    InSockInfo, SocketFDInfo, SocketInfo, SocketInfoKind, TcpSIState,
};
use libproc::libproc::proc_pid;
use libproc::libproc::proc_pid::PIDInfo;
use libproc::libproc::proc_pid::ProcType;
use libproc::libproc::proc_pid::{listpidinfo, pidinfo, ListThreads};

use std::{
    cmp, default,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use enum_primitive_derive::Primitive;
use hdrhistogram::Histogram;
use num_traits::{FromPrimitive, ToPrimitive};
use pretty_bytes::converter::convert;

/**
 * Implementation of extracting file and socket descriptors from PIDs on MacOS
 */

#[derive(Debug, Primitive)]
enum IpType {
    Ipv4 = 0x1,
    Ipv6 = 0x2,
}

#[derive(Debug, Primitive)]
enum SocketState {
    /* aka soi_state */
    NoFileTableRef = 0x0001,
    IsConnected = 0x0002,
    IsConnecting = 0x0004,
    IsDisconnecting = 0x0008,
    CantSendMore = 0x0010,
    CantReceiveMore = 0x0020,
    ReceiveAtMark = 0x0040,
    Priviledge = 0x0080,
    NonBlockingIO = 0x0100,
    AsyncIO = 0x0200,
    Incomplete = 0x0800,
    Complete = 0x1000,
    IsDisconnected = 0x2000,
    Draining = 0x4000,
}

fn tcp_state_desc(state: TcpSIState) -> &'static str {
    match state {
        // Closed
        TcpSIState::Closed => "CLOSED",
        // Listening for connection
        TcpSIState::Listen => "LISTEN",
        // Active, have sent syn
        TcpSIState::SynSent => "SYN_SENT",
        // Have send and received syn
        TcpSIState::SynReceived => "SYN_RECEIVED",
        // Established
        TcpSIState::Established => "ESTABLISHED",
        // Rcvd fin, waiting for close
        TcpSIState::CloseWait => "CLOSE_WAIT",
        // Have closed, sent fin
        TcpSIState::FinWait1 => "IN_WAIT_1",
        // Closed xchd FIN; await FIN ACK
        TcpSIState::Closing => "CLOSING",
        // Had fin and close; await FIN ACK
        TcpSIState::LastAck => "LAST_ACK",
        // Have closed, fin is acked
        TcpSIState::FinWait2 => "FIN_WAIT_2",
        // In 2*msl quiet wait after close
        TcpSIState::TimeWait => "TIME_WAIT",
        // Pseudo state: reserved
        TcpSIState::Reserved => "RESERVED",
        // Unknown
        TcpSIState::Unknown => "UNKNOWN",
    }
}

/* TODO build a map so you can look up
5 tuple (udp, sip, sp, dip, dp) -> to processes

on new connection, look up
a) /proc/net/ (linux)
b) lsof (mac) - requires spawnning processes
   lsof internals - https://github.com/apple-opensource/lsof/blob/master/lsof/

c) netstat? - buggy tcp6 implementation
d) netstat2
e) bpf filter (eg. tcpdump -k)

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

#[derive(Debug, Clone)]
pub enum SockType {
    UDP,
    TCP,
}

use std::fmt::{self, Display, Formatter};
#[derive(Debug, Clone)]
pub struct SockInfo {
    pub proto: SockType,
    pub local_port: u16,
    pub local_addr: IpAddr,
    pub remote_port: u16,
    pub remote_addr: IpAddr,
    pub pid: Option<u32>,
    pub state: Option<&'static str>,
}

impl SockInfo {
    pub fn four_tuple(&self) -> (String, u16, String, u16) {
        (
            self.local_addr.to_string(),
            self.local_port,
            self.remote_addr.to_string(),
            self.remote_port,
        )
    }
}

fn unique_tuple(tuple: (String, u16, String, u16)) -> (String, u16, String, u16) {
    let (a1, p1, a2, p2) = tuple;

    match a1.cmp(&a2) {
        cmp::Ordering::Less => (a1, p1, a2, p2),
        _ => (a2, p2, a1, p1),
    }
}

impl Display for SockInfo {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        let proto_str = format!(
            "{:?}{}",
            self.proto,
            if self.local_addr.is_ipv6() { "6" } else { "4" }
        );

        write!(
            f,
            "{}\t{}:{} -> {}:{} [{}] ({})",
            proto_str,
            self.local_addr,
            self.local_port,
            self.remote_addr,
            self.remote_port,
            self.pid.unwrap_or(0),
            self.state.unwrap_or_default()
        )
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

fn read_fd_socket(pid: u32, fd: &ProcFDInfo) -> Option<SockInfo> {
    // let process_name = match proc_pid::name(pid as i32) {
    //     Ok(name) => name,
    //     Err(_) => " - ".to_owned(),
    // };

    // let process_path = match proc_pid::pidpath(pid as i32) {
    //     Ok(name) => name,
    //     Err(_) => " - ".to_owned(),
    // };

    match fd.proc_fdtype.into() {
        ProcFDType::Socket => {
            if let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid as i32, fd.proc_fd) {
                let socket_info = socket.psi;

                // debug_socket_info(&socket_info);

                // SOI = socket info
                match socket_info.soi_kind.into() {
                    SocketInfoKind::Generic => {}
                    SocketInfoKind::In => {
                        if socket_info.soi_protocol == libc::IPPROTO_UDP {
                            let info = unsafe { socket_info.soi_proto.pri_in };
                            let sock = get_socket_info(pid, info, SockType::UDP);
                            // TODO add connection status
                            // println!("{} ({}) - {}", sock, process_name, process_path);
                            return Some(sock);
                        } else {
                            println!("Other sockets {}", pid);
                        }
                    }
                    SocketInfoKind::Tcp => {
                        // access to the member of `soi_proto` is unsafe becasuse of union type.
                        let info = unsafe { socket_info.soi_proto.pri_tcp };
                        let in_socket_info = info.tcpsi_ini;

                        // debug_socket_info(socket_info);
                        let mut sock = get_socket_info(pid, in_socket_info, SockType::TCP);

                        // println!("{} ({}) - {}", sock, process_name, process_path);
                        let state = tcp_state_desc(TcpSIState::from(info.tcpsi_state));
                        sock.state = Some(state);

                        return Some(sock);
                    }
                    // There's also UDS
                    SocketInfoKind::Un => {}
                    _ => {
                        // KernEvent, KernCtl
                        // println!("Something else? {:?}", x);
                    }
                }
            }
        }
        _ => {}
    }

    None
}

// Get sockets
pub fn get_processes_and_sockets() -> Vec<SockInfo> {
    let socks = get_processes().unwrap_or_default();
    socks
}

pub fn get_processes() -> Option<Vec<SockInfo>> {
    let pids: Vec<u32> = proc_pid::listpids(ProcType::ProcAllPIDS).ok()?;

    let socks = pids
        .into_iter()
        // get bsd info
        .filter_map(|pid| pidinfo::<BSDInfo>(pid as i32, 0).ok())
        // get prof fd info
        .filter_map(|info| {
            listpidinfo::<ListFDs>(info.pbi_pid as i32, info.pbi_nfiles as usize)
                .ok()
                .map(|f| (info.pbi_pid, f))
        })
        // get socket info
        .flat_map(|(pid, fds)| {
            fds.into_iter()
                .filter_map(move |fd| read_fd_socket(pid, &fd))
        })
        .collect();

    Some(socks)
}

fn debug_socket_info(socket_info: &SocketInfo) {
    print!("Socket state: ");
    for i in 0..14 {
        let j = 1 << i;
        if socket_info.soi_state & j > 0 {
            let socket_state = SocketState::from_i16(j).unwrap();
            print!("{:?}, ", socket_state);
        }
    }
    println!();
}

fn get_socket_info(pid: u32, in_socket_info: InSockInfo, proto: SockType) -> SockInfo {
    /* ports */
    let local_port = ntohs(in_socket_info.insi_lport);
    let dest_port = ntohs(in_socket_info.insi_fport);

    /* addr */
    let local_addr = in_socket_info.insi_laddr;
    let foreign_addr = in_socket_info.insi_faddr;

    let mut source_ip = IpAddr::from(Ipv4Addr::from(0));
    let mut dest_ip = IpAddr::from(Ipv4Addr::from(0));

    match IpType::from_u8(in_socket_info.insi_vflag) {
        Some(IpType::Ipv4) => {
            // println!("IPV4");
            let s_addr = unsafe { local_addr.ina_46.i46a_addr4.s_addr };

            let f_addr = unsafe { foreign_addr.ina_46.i46a_addr4.s_addr };

            source_ip = convert_to_ipv4(s_addr);
            dest_ip = convert_to_ipv4(f_addr);
        }
        Some(IpType::Ipv6) => {
            // println!("IPV6");
            let s_addr = unsafe { local_addr.ina_6 };

            let f_addr = unsafe { foreign_addr.ina_6 };

            source_ip = convert_to_ipv6(s_addr.s6_addr);
            dest_ip = convert_to_ipv6(f_addr.s6_addr);
        }
        _ => {}
    }

    SockInfo {
        local_addr: source_ip,
        local_port,
        remote_addr: dest_ip,
        remote_port: dest_port,
        proto,
        pid: Some(pid),
        state: None,
    }
}

fn ntohs(u: i32) -> u16 {
    u16::from_be(u as u16)
}

fn convert_to_ipv4(addr: u32) -> IpAddr {
    IpAddr::from(Ipv4Addr::from(u32::from_be(addr)))
}

fn convert_to_ipv6(addr: [u8; 16]) -> IpAddr {
    IpAddr::V6(Ipv6Addr::from(addr))
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
