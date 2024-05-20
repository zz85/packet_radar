/// BSD socket bindings
/// Implementation of extracting file and socket descriptors from PIDs on MacOS
use libproc::libproc::bsd_info::BSDInfo;
use libproc::libproc::file_info::{pidfdinfo, ListFDs, ProcFDInfo, ProcFDType};
use libproc::libproc::net_info::{
    InSockInfo, SocketFDInfo, SocketInfo, SocketInfoKind, TcpSIState,
};
use libproc::libproc::proc_pid;
use libproc::libproc::proc_pid::ProcType;
use libproc::libproc::proc_pid::{listpidinfo, pidinfo};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;

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
