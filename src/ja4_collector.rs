use std::thread;

use crossbeam::unbounded;
use packet_radar::args::Args;
use packet_radar::packet_capture::cap;
use packet_radar::pcapng;
use packet_radar::structs::{PacketInfo, PacketType};

/// JA4 processes collector
/// Mac only, Requires sudo to run with process mode
fn main() {
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

            println!("Got {msg:?}");
        }
    });

    if let Some(pcap_file) = &args.pcap_file {
        pcapng::pcap_parse(pcap_file.as_str(), tx);
        return;
    }

    cap(tx, &args)
}
