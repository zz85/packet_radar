use websocket::message::OwnedMessage;
use websocket::sender::Writer;
use websocket::sync::Server;

use std::net::TcpStream;
use std::os::unix::process;
use std::sync::{Arc, RwLock};
use std::thread;

#[macro_use]
extern crate lazy_static;
extern crate enum_primitive_derive;
extern crate num_traits;

mod dns;

mod tcp;
mod traceroute;

mod client_connection;
mod dipstick;
mod geoip;
mod packet_capture;
mod pcapng;
mod processes;
mod quic;
mod socket;
mod structs;
mod test_netstat2;
mod tls;

// use dipstick::cap;
use clap::Parser;
use client_connection::handle_clients;
use crossbeam::channel::{unbounded, Receiver};
use dns::{parse_dns, reverse_lookup};
use geoip::{asn_lookup, city_lookup, test_lookups};
use packet_capture::cap;
use structs::{ClientRequest, PacketInfo};
use tcp::parse_tcp_payload;
use traceroute::{handle_echo_reply, handle_time_exceeded};

#[derive(Parser, Debug, Clone)]
#[command(version, about, long_about = None)]
struct Args {
    // #[arg(short, long, default_value_t = true)]
    // top: bool,
    #[arg(short, long)]
    monitoring: bool,

    /// websockets support
    #[arg(short, long, default_value_t = true)]
    ws: bool,

    /// websocket bind addr
    #[arg(short, long, default_value = "127.0.0.1:3012")]
    server: String,

    #[arg(short, long, default_value_t = false)]
    tls_fingerprint: bool,

    #[arg(short, long)]
    pcap_file: Option<String>,
}

/**
 * This file starts a packet capture and a websocket server
 * Events are forwarded to connected clients
 */

fn main() {
    let args = Args::parse();

    // test_lookups()
    // let (tx, rx) = mpsc::channel();

    let (tx, rx) = unbounded();

    if args.ws {
        let bind = &args.server;
        println!(
            "Websocket server listening on {}. Open html/packet_viz.html",
            bind
        );
        let server = Server::bind(bind).unwrap();

        let clients: Arc<RwLock<Vec<Writer<TcpStream>>>> = Default::default();

        spawn_broadcast(rx.clone(), clients.clone());

        thread::spawn(|| handle_clients(server, clients));
    }

    // traceroute::set_callback(tx.clone());

    // process and bandwidth monitoring
    if args.monitoring {
        processes::start_monitoring(rx);
    }

    // runs packet capture in its thread
    // thread::spawn(move || cap(tx, &args));
    // cap(tx)
    // cap(tx, &args)

    if let Some(pcap_file) = &args.pcap_file {
        pcapng::pcap_parse(pcap_file.as_str(), tx);
    }
}

fn spawn_broadcast(rx: Receiver<PacketInfo>, clients: Arc<RwLock<Vec<Writer<TcpStream>>>>) {
    thread::spawn(move || {
        for packet_info in rx.iter() {
            let mut clients = clients.write().unwrap();

            clients.retain_mut(|c| {
                let payload = serde_json::to_string(&packet_info).unwrap();
                let message = OwnedMessage::Text(payload);

                c.send_message(&message).is_ok()
            });
        }
    });
}
