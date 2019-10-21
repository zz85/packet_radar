use netstat::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

use sysinfo::{NetworkExt, Pid, ProcessExt, ProcessorExt, Signal, System, SystemExt};

use libproc::libproc::bsd_info::BSDInfo;
use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDType};
use libproc::libproc::net_info::{SocketFDInfo, SocketInfoKind};
use libproc::libproc::proc_pid;
use libproc::libproc::proc_pid::PIDInfo;
use libproc::libproc::proc_pid::ProcType;
use libproc::libproc::proc_pid::{listpidinfo, pidinfo, ListThreads};

/* TODO build a map so you can look up
5 tuple (udp, sip, sp, dip, dp)  -> to processes

on new connection, look up
a) /proc/net/
b) lsof
c) netstat

also see https://github.com/dalance/procs - https://github.com/dalance/procs/pull/9/files
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
    if let Ok(res) = proc_pid::listpids(ProcType::ProcAllPIDS) {
        println!("{:?}", res);
        for pid in res {
            // if let Ok(r) = proc_pid::pidinfo::<SocketFDInfo>(pid as i32, 0) {
            // if let Ok(socket) = pidfdinfo::<SocketFDInfo>(pid as i32, 0) {

            if let Ok(info) = pidinfo::<BSDInfo>(pid as i32, 0) {
                if let Ok(fds) = listpidinfo::<ListFDs>(pid as i32, info.pbi_nfiles as usize) {
                    for fd in &fds {
                        match fd.proc_fdtype.into() {
                            ProcFDType::Socket => {
                                if let Ok(socket) =
                                    pidfdinfo::<SocketFDInfo>(pid as i32, fd.proc_fd)
                                {
                                    match socket.psi.soi_kind.into() {
                                        SocketInfoKind::Tcp => {
                                            // access to the member of `soi_proto` is unsafe becasuse of union type.
                                            let info = unsafe { socket.psi.soi_proto.pri_tcp };

                                            // change endian and cut off because insi_lport is network endian and 16bit witdh.
                                            let mut port = 0;
                                            port |= info.tcpsi_ini.insi_lport >> 8 & 0x00ff;
                                            port |= info.tcpsi_ini.insi_lport << 8 & 0xff00;

                                            // access to the member of `insi_laddr` is unsafe becasuse of union type.
                                            let s_addr = unsafe {
                                                info.tcpsi_ini.insi_laddr.ina_46.i46a_addr4.s_addr
                                            };

                                            // change endian because insi_laddr is network endian.
                                            let mut addr = 0;
                                            addr |= s_addr >> 24 & 0x000000ff;
                                            addr |= s_addr >> 8 & 0x0000ff00;
                                            addr |= s_addr << 8 & 0x00ff0000;
                                            addr |= s_addr << 24 & 0xff000000;

                                            println!(
                                                "pid: {} ip: {}.{}.{}.{}:{}",
                                                pid,
                                                addr >> 24 & 0xff,
                                                addr >> 16 & 0xff,
                                                addr >> 8 & 0xff,
                                                addr & 0xff,
                                                port
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
