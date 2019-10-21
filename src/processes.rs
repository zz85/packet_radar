use netstat::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

use sysinfo::{NetworkExt, Pid, ProcessExt, ProcessorExt, Signal, System, SystemExt};

use libc;
use libc::{c_int, c_void, size_t};

use libproc::libproc::bsd_info::BSDInfo;
use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::libproc::proc_pid;
use libproc::libproc::proc_pid::PIDInfo;
use libproc::libproc::proc_pid::ProcType;
use libproc::libproc::proc_pid::{listpidinfo, pidinfo, ListThreads};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/* TODO build a map so you can look up
5 tuple (udp, sip, sp, dip, dp)  -> to processes

on new connection, look up
a) /proc/net/
b) lsof
c) netstat

also see https://github.com/dalance/procs - https://github.com/dalance/procs/pull/9/files - https://github.com/dalance/procs/commit/e99a21b55121b3b99a6edc64a94ade1334bb7dee https://github.com/dalance/procs/blob/cfecc8ed37e5d34fc4f59401cd87f14b243250c7/src/process/macos.rs
https://opensource.apple.com/source/lsof/lsof-49/lsof/dialects/darwin/libproc/dsock.c
https://github.com/sveinbjornt/Sloth
https://opensource.apple.com/source/xnu/xnu-1504.15.3/bsd/sys/proc_info.h.auto.html

psutil/rsof
libutils2
https://crates.io/crates/procfs
https://github.com/andrewdavidmackenzie/libproc-rs

*/
pub fn netstats() {
    let mut sys = System::new();
    println!("total memory: {} kB", sys.get_total_memory());
    println!("used memory : {} kB", sys.get_used_memory());
    println!("total swap  : {} kB", sys.get_total_swap());
    println!("used swap   : {} kB", sys.get_used_swap());

    // netstat_mod(sys);
    processes_and_sockets();
}

fn processes_and_sockets() {
    if let Ok(pids) = proc_pid::listpids(ProcType::ProcAllPIDS) {
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
                    println!("{:?} {}",  pid, fds.len());
                    for fd in &fds {
                        match fd.proc_fdtype.into() {
                            ProcFDType::Socket => {
                                if let Ok(socket) =
                                    pidfdinfo::<SocketFDInfo>(pid as i32, fd.proc_fd)
                                {
                                    // SOI = socket info
                                    match socket.psi.soi_kind.into() {
                                        SocketInfoKind::Generic  => {
                                            println!("Generic");
                                        }
                                        SocketInfoKind::In => {
                                            if socket.psi.soi_protocol == libc::IPPROTO_UDP {
                                                let info = unsafe { socket.psi.soi_proto.pri_in };
                                                // curr_udps.push(info);
                                                // println!("UDP");
                                            } else {
                                                println!("IN");
                                            }
                                        }
                                        // There's also UDS
                                        SocketInfoKind::Tcp => {
                                            // access to the member of `soi_proto` is unsafe becasuse of union type.
                                            let info = unsafe { socket.psi.soi_proto.pri_tcp };
                                            let in_socket_info = info.tcpsi_ini;



                                            // in_sockinfo

                                            /* ports */
                                            let local_port = from_endian(in_socket_info.insi_lport);
                                            let dest_port = from_endian(in_socket_info.insi_fport);

                                            /* addr */
                                            let local_addr = in_socket_info.insi_laddr;
                                            let foreign_addr = in_socket_info.insi_faddr;

                                            // unsafe {
                                            //     match local_addr {
                                            //         ina_6 => {
                                            //             println!("IPV6");
                                            //         }
                                            //         ina_46 => {
                                            //             println!("IPV4");
                                            //         }

                                            //     }
                                            // }

                                            let mut source_ip = IpAddr::from(Ipv4Addr::from(0));
                                            let mut dest_ip = IpAddr::from(Ipv4Addr::from(0));

                                            match in_socket_info.insi_vflag {
                                                1 => {
                                                    println!("IPV4");
                                                    let s_addr = unsafe {
                                                        local_addr.ina_46.i46a_addr4.s_addr
                                                    };

                                                    let f_addr = unsafe {
                                                        foreign_addr.ina_46.i46a_addr4.s_addr
                                                    };

                                                    // source_ip = convert_ip(s_addr);
                                                    source_ip = IpAddr::from(Ipv4Addr::from(u32::from_be(s_addr)));
                                                    dest_ip = convert_ip(f_addr);
                                                }
                                                2 => {
                                                    println!("IPV6");
                                                    let s_addr = unsafe {
                                                        local_addr.ina_6
                                                    };

                                                    let f_addr = unsafe {
                                                        foreign_addr.ina_6
                                                    };

                                                    source_ip = IpAddr::V6(
                                                        Ipv6Addr::new(
                                                            s_addr.s6_addr[0].into(),
                                                            s_addr.s6_addr[1].into(),
                                                            s_addr.s6_addr[2].into(),
                                                            s_addr.s6_addr[3].into(),
                                                            s_addr.s6_addr[4].into(),
                                                            s_addr.s6_addr[5].into(),
                                                            s_addr.s6_addr[6].into(),
                                                            s_addr.s6_addr[7].into(),
                                                        )
                                                    );

                                                    dest_ip = IpAddr::V6(
                                                        Ipv6Addr::new(
                                                            f_addr.s6_addr[0].into(),
                                                            f_addr.s6_addr[1].into(),
                                                            f_addr.s6_addr[2].into(),
                                                            f_addr.s6_addr[3].into(),
                                                            f_addr.s6_addr[4].into(),
                                                            f_addr.s6_addr[5].into(),
                                                            f_addr.s6_addr[6].into(),
                                                            f_addr.s6_addr[7].into(),
                                                        )
                                                    );
                                                }
                                                _  => {}
                                            }

                                            // access to the member of `insi_laddr` (local addr) is unsafe becasuse of union type.


                                            println!(
                                                "pid: {} ip: {}:{} -> {}:{}",
                                                pid,
                                                source_ip,
                                                local_port,
                                                dest_ip,
                                                dest_port,
                                            );
                                        }
                                        _ => (),
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

pub fn ntohs(u: u16) -> u16 {
    u16::from_be(u)
}

#[cfg_attr(tarpaulin, skip)]
#[cfg(target_os = "macos")]
pub fn change_endian(val: u32) -> u32 {
    // u32::from_be(val)
    let mut ret = 0;
    ret |= val >> 24 & 0x000000ff;
    ret |= val >> 8 & 0x0000ff00;
    ret |= val << 8 & 0x00ff0000;
    ret |= val << 24 & 0xff000000;
    ret
}

pub fn from_endian(val: i32) -> i32 {
    // let mut port = 0;
    // port |= val >> 8 & 0x00ff;
    // port |= val << 8 & 0xff00;
    // port
    ntohs(val as u16) as i32
}

fn convert_ip(addr: u32) -> IpAddr {
    let addr = change_endian(addr);

    IpAddr::V4(Ipv4Addr::new(
        (addr >> 24 & 0xff) as u8,
        (addr >> 16 & 0xff) as u8,
        (addr >> 8 & 0xff) as u8,
        (addr & 0xff) as u8,
    ))
}

fn netstat_mod(sys: &mut System) {
    // // ipv6 call crash
    // let af_flags = AddressFamilyFlags::IPV4; // | AddressFamilyFlags::IPV6;
    // let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    // let sockets_info = get_sockets_info(af_flags, proto_flags).unwrap();
    // for si in sockets_info {
    //     // println!("{:?}",  si);
    //     match si.protocol_socket_info {
    //         ProtocolSocketInfo::Tcp(tcp_si) => {
    //             println!(
    //                 "TCP {}:{} -> {}:{} {:?} - {}",
    //                 tcp_si.local_addr,
    //                 tcp_si.local_port,
    //                 tcp_si.remote_addr,
    //                 tcp_si.remote_port,
    //                 si.associated_pids,
    //                 tcp_si.state
    //             );

    //             for pid in si.associated_pids {
    //                 get_pid_info(&mut sys, pid);
    //             }
    //         }
    //         ProtocolSocketInfo::Udp(udp_si) => {
    //             println!(
    //                 "UDP {}:{} -> *:* {:?}",
    //                 udp_si.local_addr, udp_si.local_port, si.associated_pids
    //             );

    //             for pid in si.associated_pids {
    //                 get_pid_info(&mut sys, pid);
    //             }
    //         }
    //     }
    // }
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
