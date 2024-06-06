use std::thread;

use crossbeam::unbounded;
use packet_radar::args::Args;
use packet_radar::packet_capture::{cap, is_local};
use packet_radar::pcapng;
use packet_radar::structs::{PacketInfo, PacketType};
use tracing::info;
use tracing_subscriber;

/// JA4 process collector
/// sniffer/tail/snoop/dump/trace
/// Mac only, uses sudo to run with process mode
fn main() {
    tracing_subscriber::fmt::init();

    let mut args = Args::default();
    args.pcap_file = Some("!".into());

    let (tx, rx) = unbounded::<PacketInfo>();

    // Update connection tracker based on packets received
    thread::spawn(move || {
        for msg in rx.iter() {
            match msg.t {
                PacketType::Ja4 => {}
                _ => {
                    continue;
                }
            };

            // info!("Got {msg:?}");

            let ja4 = msg.ja4.unwrap_or_default();
            let sni = msg.sni.unwrap_or("-".into());
            let pid = msg.pid.unwrap_or(0);
            let process = msg.process.unwrap_or("<unknown>".into());
            let PacketInfo {
                src,
                src_port,
                dest,
                dest_port,
                ..
            } = msg;

            match src.parse() {
                Ok(ip) => {
                    if !is_local(&ip) {
                        continue;
                    }
                }
                _ => {
                    continue;
                }
            };

            // info!("{ja4}\t {process}({pid})\t{sni}\t{src}:{src_port}→ {dest}:{dest_port}");

            info!("{ja4}\t {process} ({pid})\t{sni} ({dest}:{dest_port})");
        }
    });

    if let Some(pcap_file) = &args.pcap_file {
        pcapng::pcap_parse(pcap_file.as_str(), tx);
        return;
    }

    cap(tx, &args)
}
