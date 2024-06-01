use crossterm::{
    cursor,
    style::{self, Stylize},
    terminal, ExecutableCommand, QueueableCommand,
};
use std::{
    collections::{HashMap, HashSet},
    time::Duration,
};
use std::{
    io::{self, Write},
    thread,
};

use crossbeam::unbounded;
use packet_radar::pcapng;
use packet_radar::structs::PacketInfo;
use packet_radar::tcp::TCP_STATS;
use tracing::info;
use tracing_subscriber;

/// JA4 process collector
/// Mac only, uses sudo to run with process mode
fn main() -> io::Result<()> {
    tracing_subscriber::fmt::init();

    let (tx, _rx) = unbounded::<PacketInfo>();

    thread::spawn(move || pcapng::pcap_parse("!", tx));

    let mut stdout = io::stdout();

    #[derive(Default, Debug)]
    struct ProcInfo {
        ja4: HashSet<String>,
        pids: HashSet<u32>,
    }

    loop {
        stdout.execute(terminal::Clear(terminal::ClearType::All))?;
        stdout
            .queue(cursor::MoveTo(0, 0))?
            .queue(style::PrintStyledContent(
                "JA4 + Processes (refresh 5 seconds)\n".magenta(),
            ))?;

        let mut process_to_ja4 = HashMap::<_, ProcInfo>::new();
        for conn in TCP_STATS.conn_map.iter() {
            if let Some(ja4) = &conn.ja4 {
                let pid = &conn.pid.unwrap_or(0);
                let default = "".to_owned();
                let process = conn.process_name.clone().unwrap_or_else(|| default);
                // info!("{ja4} {process} {pid}");

                let entry = process_to_ja4.entry(process).or_default();
                entry.ja4.insert(ja4.clone());
                entry.pids.insert(*pid);
            }
        }

        info!("{process_to_ja4:#?}");
        stdout.flush()?;
        std::thread::sleep(Duration::from_millis(5000));
    }
}
