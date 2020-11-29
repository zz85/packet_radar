#![feature(drain_filter)]
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
use processes::processes_and_sockets;

mod test_netstat2;
use test_netstat2::{get_sys, test_netstat2};

mod structs;
use structs::{ClientRequest, PacketInfo};

mod client_connection;
use client_connection::handle_clients;

mod geoip;
use geoip::{asn_lookup, city_lookup, test_lookups};

mod packet_capture;
use packet_capture::cap;

use std::convert::TryFrom;

use std::time::Instant;

/**
 * This file starts a packet capture and a websocket server
 * Events are forwarded to connected clients
 */

fn main() {
    // Test experimentation
    println!("Native MacOS network descriptions");
    println!("===============");
    let start = Instant::now();
    processes_and_sockets();
    println!("netstat1 {:?}", start.elapsed());

    println!("Test netstat 2");
    println!("===============");
    let start = Instant::now();
    test_netstat2();
    println!("netstat2 {:?}", start.elapsed());

    /* track connection, lookup connections to pid, count pid ++ */

    // test_lookups();

    // let bind = env::args().nth(1).unwrap_or("127.0.0.1:3012".to_owned());
    // println!(
    //     "Websocket server listening on {}. Open html/packet_viz.html",
    //     bind
    // );
    // let server = Server::bind(bind).unwrap();

    // let clients: Arc<RwLock<Vec<Writer<TcpStream>>>> = Default::default();

    // // let (tx, rx) = mpsc::channel();
    // let (tx, rx) = unbounded();

    // spawn_broadcast(rx, clients.clone());

    // traceroute::set_callback(tx.clone());

    // thread::spawn(move || cap(tx));

    // handle_clients(server, clients);
}

fn spawn_broadcast(rx: Receiver<OwnedMessage>, clients: Arc<RwLock<Vec<Writer<TcpStream>>>>) {
    thread::spawn(move || {
        for message in rx.iter() {
            clients
                .write()
                .unwrap()
                .drain_filter(|c| c.send_message(&message).is_err());
        }
    });
}
