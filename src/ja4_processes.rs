use std::thread;
use std::time::Duration;

use crossbeam::unbounded;
use packet_radar::pcapng;
use packet_radar::structs::PacketInfo;
use packet_radar::tcp::TCP_STATS;
use tracing::info;
use tracing_subscriber;

/// JA4 process collector
/// Mac only, uses sudo to run with process mode
fn main() {
    tracing_subscriber::fmt::init();

    let (tx, _rx) = unbounded::<PacketInfo>();

    thread::spawn(|| loop {
        println!("Processes");
        for conn in TCP_STATS.conn_map.iter() {
            if let Some(ja4) = &conn.ja4 {
                let pid = conn.pid.unwrap_or(0);
                let default = "".to_owned();
                let process = conn.process_name.as_ref().unwrap_or_else(|| &default);
                info!("{ja4} {process} {pid}");
            }
        }
        std::thread::sleep(Duration::from_millis(5000));
    });

    pcapng::pcap_parse("!", tx);
}
