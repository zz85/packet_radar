use crossterm::{
    cursor,
    style::{self, Stylize},
    terminal, ExecutableCommand, QueueableCommand,
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
#[cfg(feature = "df")]
fn main() -> io::Result<()> {
    // tracing_subscriber::fmt::init();

    let (tx, _rx) = unbounded::<PacketInfo>();

    thread::spawn(move || pcapng::pcap_parse("!", tx));

    let mut stdout = io::stdout();

    loop {
        stdout.execute(terminal::Clear(terminal::ClearType::All))?;
        stdout
            .queue(cursor::MoveTo(0, 0))?
            .queue(style::PrintStyledContent(
                "JA4 + Processes (refresh 5 seconds)\n".magenta(),
            ))?;

        let mut ja4s = Vec::new();
        let mut processes = Vec::new();
        let mut pids = Vec::new();
        let mut snis = Vec::new();

        for conn in TCP_STATS.conn_map.iter() {
            if let Some(ja4) = &conn.ja4 {
                let pid = &conn.pid.unwrap_or(0);
                let process = conn.process_name.clone().unwrap_or_default();
                let sni = conn.sni.as_ref().map(|v| v.to_owned()).unwrap_or_default();
                // info!("{ja4} {process} {pid}");

                ja4s.push(ja4.clone());
                processes.push(process);
                pids.push(*pid);
                snis.push(sni);
            }
        }

        use polars::prelude::*;
        let df = df!(
            "ja4" => &ja4s,
            "process" => &processes,
            "pid" => &pids,
            "sni" => snis
        )
        .unwrap();

        // println!("{}", df);
        let sort_by_process = df
            .clone()
            .lazy()
            .group_by(["process"])
            .agg([col("ja4").unique(), len().alias("handshakes")])
            .collect();

        println!("{sort_by_process:?}");

        let sort_by_ja4 = df
            .clone()
            .lazy()
            .group_by(["ja4"])
            .agg([col("process").unique(), len()])
            .collect();

        println!("{sort_by_ja4:?}");
        stdout.flush()?;
        std::thread::sleep(std::time::Duration::from_millis(5000));
    }
}

#[cfg(not(feature = "df"))]
fn main() {
    println!("feature df needs to be enabled!");
}
