use std::time::Instant;

use netstat2::{get_sockets_info, AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};

pub fn test_netstat2() {
    let af_flags = AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6;
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = match get_sockets_info(af_flags, proto_flags) {
        Ok(sockets_info) => sockets_info,
        Err(e) => {
            println!("{:?}", e);
            return;
        }
    };

    let now = Instant::now();
    let sys = get_sys();
    println!("Get sys time: {:?}", now.elapsed());

    println!("netstat2 socket count: {}", sockets_info.len());

    for si in sockets_info {
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
                    get_pid_info(&sys, pid);
                }
            }
            ProtocolSocketInfo::Udp(udp_si) => {
                println!(
                    "UDP {}:{} -> *:* {:?}",
                    udp_si.local_addr, udp_si.local_port, si.associated_pids
                );

                for pid in si.associated_pids {
                    get_pid_info(&sys, pid);
                }
            }
        }
    }
}

/*
 * build_hash_of_pids_by_inode() returns hashmap of inodes -> pids
 * it's done by  iterating pids, getting its file descriptiors inodes,
 * filtering to sockets only.
 *
 * see more https://github.com/ohadravid/netstat2-rs/
 * this probably can replace netstat or my custom implemntation of netstat
 */

use sysinfo::{RefreshKind, System};

pub fn get_sys() -> System {
    /* uses sys crate */
    // let sys = System::new();
    let sys = System::new_with_specifics(RefreshKind::everything());

    println!("total memory: {} kB", sys.total_memory());
    println!("used memory : {} kB", sys.used_memory());
    println!("total swap  : {} kB", sys.total_swap());
    println!("used swap   : {} kB", sys.used_swap());

    sys
}

fn get_pid_info(sys: &System, pid: u32) {
    // let pid_str = format!("{}", pid);
    // if let Ok(pid) = Pid::from(pid) {
    match sys.process((pid as usize).into()) {
        Some(p) => {
            // println!(
            //     "{}\t{:?}\t{}\t{}\t{}",
            //     p.name(),
            //     p.exe(),
            //     p.memory(),
            //     p.status(),
            //     p.start_time()
            // );
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

// 4/5 ms
// 300 for getting proc ids

// pids - 5s
