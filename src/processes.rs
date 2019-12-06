use netstat::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

use sysinfo::{NetworkExt, Pid, ProcessExt, ProcessorExt, Signal, System, SystemExt};

use libc;
use libc::{c_int, c_void, size_t};

use libproc::libproc::bsd_info::BSDInfo;
use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind, InSockInfo, SocketInfo, TcpSIState};
use libproc::libproc::proc_pid;
use libproc::libproc::proc_pid::PIDInfo;
use libproc::libproc::proc_pid::ProcType;
use libproc::libproc::proc_pid::{listpidinfo, pidinfo, ListThreads};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use num_traits::{FromPrimitive, ToPrimitive};
use enum_primitive_derive::Primitive;

pub fn netstats() {
    /* uses sys crate */
    let mut sys = System::new();

    println!("total memory: {} kB", sys.get_total_memory());
    println!("used memory : {} kB", sys.get_used_memory());
    println!("total swap  : {} kB", sys.get_total_swap());
    println!("used swap   : {} kB", sys.get_used_swap());

    /* unfortunately sys crate is a little buggy reading tcp6 sockets */
    /* while for mac, sys uses c bindings to get memory, it's forking netstat for following */
    // netstat_mod(sys);

    /* use lower level libproc for mac sockets */
    processes_and_sockets();
}

#[derive(Debug, Primitive)]
enum IpType {
    Ipv4 = 0x1,
    Ipv6 = 0x2,
}

#[derive(Debug, Primitive)]
enum SocketState { /* aka soi_state */
    NoFileTableRef = 0x0001,
    IsConnected = 0x0002,
    IsConnecting = 0x0004,
    IsDisconnecting = 0x0008,
    CantSendMore = 0x0010,
    CantReceiveMore = 0x0020,
    ReceiveAtMark = 0x0040,
    Priviledge =  0x0080,
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
5 tuple (udp, sip, sp, dip, dp)  -> to processes

on new connection, look up
a) /proc/net/ (linux)
b) lsof (mac)
c) netstat?

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


fn get_pid_path(pid: u32) -> Result<String, String> {
    proc_pid::pidpath(pid as i32)
}

/* proc pid: proc_listpids, proc_name, proc_pidinfo, proc_regionfilename, proc_pidpath */

fn processes_and_sockets() {
    if let Ok(pids) = proc_pid::listpids(ProcType::ProcAllPIDS) {
        // TODO clean this up
        // pids
        //     .iter()
        //     .map(|pid| pidinfo::<BSDInfo>(pid as i32, 0))
        //     .map(|info| listpidinfo::<ListFDs>(pid as i32, info.pbi_nfiles as usize))
        //     .map(|ref fds| fds.iter())
        //     .map(|fd| {
        //         match fd.proc_fdtype.into() {
        //             ProcFDType::Socket => {
        //                 if let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid as i32, fd.proc_fd) {
        //                 }
        //             }
        //         }
        //     });

        for pid in pids {
            if let Ok(info) = pidinfo::<BSDInfo>(pid as i32, 0) {
                if let Ok(fds) = listpidinfo::<ListFDs>(pid as i32, info.pbi_nfiles as usize) {
                    // println!("{:?} {}",  pid, fds.len());
                    for fd in &fds {
                        match fd.proc_fdtype.into() {
                            ProcFDType::Socket => {
                                if let Ok(socket) =
                                    pidfdinfo::<SocketFDInfo>(pid as i32, fd.proc_fd)
                                {
                                    let socket_info = socket.psi;
                                    // debug_socket_info(socket_info);

                                    // SOI = socket info
                                    match socket_info.soi_kind.into() {
                                        SocketInfoKind::Generic  => {
                                            println!("Generic");
                                        }
                                        SocketInfoKind::In => {
                                            if socket_info.soi_protocol == libc::IPPROTO_UDP {
                                                let info = unsafe { socket_info.soi_proto.pri_in };
                                                // curr_udps.push(info);
                                                // println!("UDP");
                                                get_socket_info(pid, info, "udp");

                                            } else {
                                                println!("Other sockets");
                                            }
                                        }
                                        SocketInfoKind::Tcp => {
                                            // access to the member of `soi_proto` is unsafe becasuse of union type.
                                            let info = unsafe { socket_info.soi_proto.pri_tcp };
                                            let in_socket_info = info.tcpsi_ini;
                                            print!("({}) ", tcp_state_desc(TcpSIState::from(info.tcpsi_state)));
                                            get_socket_info(pid, in_socket_info, "tcp");
                                            // debug_socket_info(socket_info);
                                        }
                                        // There's also UDS
                                        SocketInfoKind::Un => {

                                        }
                                        _ => {
                                            // KernEvent, KernCtl
                                            // println!("Something else? {:?}", x);
                                        }
                                    }
                                }
                            }
                            _ => (),
                        }
                    }
                }
            }
        }
    }
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

fn get_socket_info(pid:u32, in_socket_info: InSockInfo, proto: &str) {
    /* ports */
    let local_port = ntohs(in_socket_info.insi_lport);
    let dest_port = ntohs(in_socket_info.insi_fport);

    /* addr */
    let local_addr = in_socket_info.insi_laddr;
    let foreign_addr = in_socket_info.insi_faddr;

    let mut source_ip = IpAddr::from(Ipv4Addr::from(0));
    let mut dest_ip = IpAddr::from(Ipv4Addr::from(0));

    let mut ip_type = 4;
    match IpType::from_u8(in_socket_info.insi_vflag) {
        Some(IpType::Ipv4) => {
            // println!("IPV4");
            let s_addr = unsafe {
                local_addr.ina_46.i46a_addr4.s_addr
            };

            let f_addr = unsafe {
                foreign_addr.ina_46.i46a_addr4.s_addr
            };

            source_ip = convert_to_ipv4(s_addr);
            dest_ip = convert_to_ipv4(f_addr);
        }
        Some(IpType::Ipv6) => {
            // println!("IPV6");
            let s_addr = unsafe {
                local_addr.ina_6
            };

            let f_addr = unsafe {
                foreign_addr.ina_6
            };

            source_ip = convert_to_ipv6(s_addr.s6_addr);
            dest_ip = convert_to_ipv6(f_addr.s6_addr);

            ip_type = 6;
        }
        _  => {}
    }

    // TODO add connection status

    let name = format!("{:?}", proc_pid::name(pid as i32));

    if dest_port > 0 {
        println!(
                "pid: {} [{}{}] [{}]:{} -> [{}]:{} {}",
                pid,
                proto,
                ip_type,
                source_ip,
                local_port,
                dest_ip,
                dest_port,
                name,
            );
    }
    else {
        println!(
                "pid: {} [{}{}] [{}]:{} {}",
                pid,
                proto,
                ip_type,
                source_ip,
                local_port,
                name,
            );
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

/* this can be used, but it crashes on IPv6 sockets */
fn netstat_mod(sys: &mut System) {
    // ipv6 call crash
    let af_flags = AddressFamilyFlags::IPV4; // | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = get_sockets_info(af_flags, proto_flags).unwrap();
    for si in sockets_info {
        // println!("{:?}",  si);
        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_si) => {
                println!(
                    "TCP {}:{} -> {}:{} {:?} - {}",
                    tcp_si.local_addr,
                    tcp_si.local_port,
                    tcp_si.remote_addr,
                    tcp_si.remote_port,
                    si.associated_pids,
                    tcp_si.state
                );

                for pid in si.associated_pids {
                    get_pid_info(&mut sys, pid);
                }
            }
            ProtocolSocketInfo::Udp(udp_si) => {
                println!(
                    "UDP {}:{} -> *:* {:?}",
                    udp_si.local_addr, udp_si.local_port, si.associated_pids
                );

                for pid in si.associated_pids {
                    get_pid_info(&mut sys, pid);
                }
            }
        }
    }
}

fn get_pid_info(sys: &mut System, pid: u32) {
    // let pid_str = format!("{}", pid);
    // if let Ok(pid) = Pid::from(pid) {
    match sys.get_process(pid as i32) {
        Some(p) => {
            println!(
                "{}\t{:?}\t{}\t{}\t{}",
                p.name(),
                p.exe(),
                p.memory(),
                p.status(),
                p.start_time()
            );
            // cpu_usage()
            // println!("{:?}", *p)
            // https://github.com/GuillaumeGomez/sysinfo/blob/74602704a7e21192c08fce1fc9cce5d126e7b632/src/mac/process.rs#L172
            // executable path, current working directory
            // cpu, root path, parent
            // command,  memory, environment
        }
        None => println!("pid \"{:?}\" not found", pid),
    };
}
