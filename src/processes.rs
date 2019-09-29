use netstat::{
    get_sockets_info,
    AddressFamilyFlags,
    ProtocolFlags,
    ProtocolSocketInfo,
};

/* TODO build a map so you can look up
5 tuple (udp, sip, sp, dip, dp)  -> to processes

on new connection, look up  
a) /proc/net/
b) lsof
c) netstat
*/
pub fn netstats() {
    let af_flags = AddressFamilyFlags::IPV4;  // | AddressFamilyFlags::IPV6
    let proto_flags = ProtocolFlags::TCP | ProtocolFlags::UDP;
    let sockets_info = get_sockets_info(af_flags, proto_flags).unwrap();
    for si in sockets_info {
        // println!("{:?}",  si);
        match si.protocol_socket_info {
            ProtocolSocketInfo::Tcp(tcp_si) => println!(
                "TCP {}:{} -> {}:{} {:?} - {}",
                tcp_si.local_addr,
                tcp_si.local_port,
                tcp_si.remote_addr,
                tcp_si.remote_port,
                si.associated_pids,
                tcp_si.state
            ),
            ProtocolSocketInfo::Udp(udp_si) => println!(
                "UDP {}:{} -> *:* {:?}",
                udp_si.local_addr, udp_si.local_port, si.associated_pids
            ),
        }
    }
}