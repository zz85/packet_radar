use websocket::message::OwnedMessage;
use websocket::sender::Writer;
use websocket::sync::Server;

use std::env;

use std::net::TcpStream;
use std::sync::{Arc, RwLock};
use std::thread;

#[macro_use]
extern crate lazy_static;
extern crate enum_primitive_derive;
extern crate num_traits;

mod dns;
use dns::{parse_dns, reverse_lookup};

mod tcp;
use tcp::parse_tcp_payload;

mod traceroute;
use traceroute::{handle_echo_reply, handle_time_exceeded};

use crossbeam::channel::{unbounded, Receiver};

mod processes;

mod test_netstat2;

mod structs;
use structs::{ClientRequest, PacketInfo};

mod client_connection;
use client_connection::handle_clients;

mod geoip;
use geoip::{asn_lookup, city_lookup, test_lookups};

mod packet_capture;
use packet_capture::cap;

mod quic;

mod tls;

use clap::Parser;

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

    // process and bandiwth monitoring
    if args.monitoring {
        processes::start_monitoring(rx);
    }

    // runs packet capture in its thread
    // thread::spawn(move || cap(tx, &args));
    cap(tx, &args)
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
