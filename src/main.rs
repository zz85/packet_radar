use clap::Parser;
use crossbeam::{unbounded, Receiver};
use packet_radar::args::Args;
use packet_radar::client_connection::handle_clients;
use packet_radar::packet_capture::cap;
use packet_radar::structs::PacketInfo;
use packet_radar::{pcapng, processes};
use websocket::message::OwnedMessage;
use websocket::sender::Writer;
use websocket::sync::Server;

use std::net::TcpStream;
use std::sync::{Arc, RwLock};
use std::thread;

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

    if let Some(pcap_file) = &args.pcap_file {
        pcapng::pcap_parse(pcap_file.as_str(), tx);
        return;
    }

    // runs packet capture in its thread
    // thread::spawn(move || cap(tx, &args));
    // cap(tx)
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
