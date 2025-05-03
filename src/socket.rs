#[cfg(any(target_os = "macos", doc))]
use socket_mac::get_processes;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use enum_primitive_derive::Primitive;
use num_traits::FromPrimitive;

#[derive(Debug, Primitive)]
enum IpType {
    Ipv4 = 0x1,
    Ipv6 = 0x2,
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

#[derive(Debug, Clone, Default)]
struct ProcessMeta {
    pid: u32,
    name: String,
    process_path: String,
    bytes: u64,
    bytes_recv: u64,
    bytes_sent: u64,
}

pub fn get_processes() -> Option<Vec<SockInfo>> {
    None
}

