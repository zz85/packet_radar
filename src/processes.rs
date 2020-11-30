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
    cmp,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};

use enum_primitive_derive::Primitive;
use num_traits::{FromPrimitive, ToPrimitive};

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
c) netstat? - buggy tcp6 implementation
d) netstat2

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
    pub pid: u32,
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
            "{}\t{}:{} -> {}:{} [{}]",
            proto_str,
            self.local_addr,
            self.local_port,
            self.remote_addr,
            self.remote_port,
            self.pid
        )
    }
}

use std::collections::HashMap;
use std::sync::RwLock;
use std::thread;
use std::time::{Duration, Instant};

// lazy_static! {
//     pub static ref CONNECTIONS: RwLock<HashMap<String, String>> = Default::default();
//     pub static ref PROCESSES: RwLock<HashMap<u32, String>> = Default::default();
// }

#[derive(Debug, Clone)]
struct ProcessMeta {
    pid: u32,
    name: String,
    bytes: u64,
}

use crate::PacketInfo;

pub fn start_monitoring(rx: Receiver<PacketInfo>) {
    // TODO move these into a single protected struct and avoid unwraps!
    let mut connections: Arc<RwLock<HashMap<(String, u16, String, u16), u32>>> = Default::default();
    let mut processes: Arc<RwLock<HashMap<u32, ProcessMeta>>> = Default::default();

    let connections1 = connections.clone();
    let processes1 = processes.clone();

    thread::spawn(move || {
        let connections = connections1;
        for msg in rx.iter() {
            // println!("Got {:?}", msg);

            let tuple = unique_tuple((msg.src, msg.src_port, msg.dest, msg.dest_port));
            let connections = connections.read().unwrap();
            let v = connections.get(&tuple);

            if v.is_some() {
                let mut processes = processes1.write().unwrap();
                let len = msg.len;
                let pid = v.unwrap();
                processes.entry(*pid).and_modify(|e| e.bytes += len as u64);
            } else {
                // println!("no");
            }
        }
    });

    let top_processes = processes.clone();

    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(3000));

        let mut top: Vec<ProcessMeta> = top_processes.read().unwrap().values().cloned().collect();
        top.sort_by(|a, b| b.bytes.cmp(&a.bytes));
        println!("Top");
        top[..5].into_iter().for_each(|v| println!("{:?}", v));
    });

    let connections2 = connections.clone();
    thread::spawn(move || {
        let connections = connections2;
        loop {
            println!("processes_and_sockets");
            thread::sleep(Duration::from_millis(1500));
            let start = Instant::now();
            let sockets = processes_and_sockets();
            let s: Vec<SockInfo> = sockets
                .into_iter()
                .filter(|sock| !processes.read().unwrap().contains_key(&sock.pid))
                .collect();

            s.iter().for_each(|sock| {
                let process_path = match proc_pid::pidpath(sock.pid as i32) {
                    Ok(name) => name,
                    Err(_) => " - ".to_owned(),
                };

                let meta = ProcessMeta {
                    pid: sock.pid,
                    name: process_path,
                    bytes: 0,
                };

                processes.write().unwrap().insert(sock.pid, meta);
            });

            s.iter().for_each(|s| {
                connections
                    .write()
                    .unwrap()
                    .insert(unique_tuple(s.four_tuple()), s.pid);
            });
        }
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
    // }

    match fd.proc_fdtype.into() {
        ProcFDType::Socket => {
            if let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid as i32, fd.proc_fd) {
                let socket_info = socket.psi;
                // debug_socket_info(socket_info);

                // SOI = socket info
                match socket_info.soi_kind.into() {
                    SocketInfoKind::Generic => {
                        println!("Generic");
                    }
                    SocketInfoKind::In => {
                        if socket_info.soi_protocol == libc::IPPROTO_UDP {
                            let info = unsafe { socket_info.soi_proto.pri_in };
                            let sock = get_socket_info(pid, info, SockType::UDP);
                            // TODO add connection status
                            // print!("{} ({})", sock, process_name);
                            // println!("");
                            return Some(sock);
                        } else {
                            println!("Other sockets");
                        }
                    }
                    SocketInfoKind::Tcp => {
                        // access to the member of `soi_proto` is unsafe becasuse of union type.
                        let info = unsafe { socket_info.soi_proto.pri_tcp };
                        let in_socket_info = info.tcpsi_ini;

                        // debug_socket_info(socket_info);
                        let sock = get_socket_info(pid, in_socket_info, SockType::TCP);
                        // print!("{} ({})", sock, process_name);
                        // print!(" - {}", tcp_state_desc(TcpSIState::from(info.tcpsi_state)));
                        // println!("");

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
pub fn processes_and_sockets() -> Vec<SockInfo> {
    let socks: Vec<SockInfo> = proc_pid::listpids(ProcType::ProcAllPIDS)
        .ok()
        .map(|pids| {
            pids.into_iter()
                .filter_map(|pid| pidinfo::<BSDInfo>(pid as i32, 0).ok())
                .filter_map(|info| {
                    listpidinfo::<ListFDs>(info.pbi_pid as i32, info.pbi_nfiles as usize)
                        .ok()
                        .map(|f| (info.pbi_pid, f))
                })
                .flat_map(|(pid, fds)| {
                    fds.into_iter()
                        .filter_map(move |fd| read_fd_socket(pid, &fd))
                })
                .collect()
        })
        .unwrap_or_default();

    // socks.iter().for_each(|v| println!("{}", v));

    socks
}

fn debug_socket_info(socket_info: SocketInfo) {
    print!("Socket state: ");
    for i in 0..14 {
        let j = 1 << i;
        if socket_info.soi_state & j > 0 {
            let socket_state = SocketState::from_i16(j).unwrap();
            print!("{:?}, ", socket_state);
        }
    }
    println!("");
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
        pid,
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

fn test() {
    use crate::test_netstat2::{get_sys, test_netstat2};
    use std::time::Instant;

    // Test experimentation
    println!("Native MacOS network descriptions");
    println!("===============");
    let start = Instant::now();
    processes_and_sockets();
    println!("netstat1 {:?}", start.elapsed());

    println!("Test netstat 2");
    println!("===============");
    let start = Instant::now();
    test_netstat2();
    println!("netstat2 {:?}", start.elapsed());

    /* track connection, lookup connections to pid, count pid ++ */
}
