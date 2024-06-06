use crossbeam::Receiver;
use websocket::message::OwnedMessage;
use websocket::sender::Writer;
use websocket::server::WsServer;

use std::net::TcpStream;
use std::sync::{Arc, RwLock};
use std::thread;

use serde_json::json;

use super::traceroute;
use crate::dns::reverse_lookup;
use crate::geoip::{asn_lookup, city_lookup};
use crate::structs::{ClientRequest, PacketInfo};

/// pass packet info data to all connected web clients (through websockets)
pub fn spawn_broadcast(rx: Receiver<PacketInfo>, clients: Arc<RwLock<Vec<Writer<TcpStream>>>>) {
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

/// main websocket server loop
pub fn handle_clients(
    server: WsServer<websocket::server::NoTlsAcceptor, std::net::TcpListener>,
    clients: Arc<RwLock<Vec<Writer<TcpStream>>>>,
) {
    for connection in server.filter_map(Result::ok) {
        let clients = clients.clone();

        thread::spawn(move || {
            let ws = connection.accept().unwrap();
            let ip = ws.peer_addr().unwrap();
            let (mut rx, ws_tx) = ws.split().unwrap();

            // add writer streams to shared vec
            clients.write().unwrap().push(ws_tx);

            // receive messages from web clients
            for message in rx.incoming_messages() {
                let message = message.unwrap();

                match message {
                    OwnedMessage::Close(_) => {
                        // let message = OwnedMessage::Close(None);
                        // tx.send_message(&message).unwrap();
                        println!("Client {} disconnected", ip);
                        return;
                    }
                    OwnedMessage::Text(text) => {
                        // json parse request here
                        let data = serde_json::from_str(&text);
                        let data: ClientRequest = match data {
                            Ok(data) => data,
                            Err(error) => {
                                println!("Problem parsing: {:?}", error);
                                break;
                            }
                        };

                        let req = data.req;
                        // println!("data req: {}, val: {}", req, data.value);

                        match req.as_ref() {
                            "lookup" => {
                                // handle look up address
                                let ip = data.value;
                                let hostname = reverse_lookup(&ip).unwrap_or(format!("{ip}"));
                                // println!("Name look up from: {} to {}", destination, hostname);

                                let p = json!({
                                    "type": "lookup_addr",
                                    "ip": ip,
                                    "hostname": hostname,
                                })
                                .to_string();

                                web_broadcast(&clients, p);
                            }
                            "local_addr" => {
                                let interfaces = pnet::datalink::interfaces();
                                for interface in interfaces {
                                    // println!("Interface {:?}", interface.ips);

                                    for ip in interface.ips {
                                        let src = ip.ip();

                                        let p = json!({
                                            "type": "local_addr",
                                            "ip": src,
                                        })
                                        .to_string();

                                        web_broadcast(&clients, p);
                                    }
                                }
                            }
                            "traceroute" => {
                                let ip = data.value;
                                println!("ip {}", ip);
                                // ws.send(JSON.stringify({ req: 'traceroute', value: '1.1.1.1'}))
                                match ip.parse() {
                                    Ok(addr) => {
                                        println!("Addr {}", addr);
                                        traceroute::traceroute(addr);
                                    }
                                    Err(e) => {
                                        println!("Can't parse ip {}, {}", ip, e);
                                    }
                                };
                            }
                            "geoip" => {
                                let ip = data.value;
                                if let Some(r) = get_geo_ip(ip) {
                                    web_broadcast(&clients, r)
                                };
                            }
                            "processes" => {}
                            "sockets" => {}
                            _ => {}
                        }

                        // handle filtering
                        // handle get buffers
                    }
                    OwnedMessage::Binary(_buf) => {}
                    others => {
                        println!("ok {:?}", others);
                    }
                }
            }
        });
    }
}

// Sends events out to all connection clients
fn web_broadcast(clients: &RwLock<Vec<Writer<TcpStream>>>, text: String) {
    println!("Broadcasting... {}", text);
    let message = OwnedMessage::Text(text);
    let mut clients = clients.write().unwrap();

    clients.retain_mut(|c| c.send_message(&message).is_ok());
}

fn get_geo_ip(ip: String) -> Option<String> {
    println!("Geo Ip {}", ip);
    match ip.parse() {
        Ok(addr) => {
            let city = match city_lookup(addr) {
                Ok(city) => city,
                Err(e) => {
                    println!("Cant look up {:?}", e);
                    return None;
                }
            };
            let asn = match asn_lookup(addr) {
                Ok(asn) => asn,
                Err(e) => {
                    println!("Cant look up {:?}", e);
                    return None;
                }
            };
            println!("City {:?}", city);
            println!("Asn {:?}", asn);

            let loc = city.location?;
            let country = city.registered_country?;
            // let rep = city.represented_country?;

            let city_name = city
                .city
                .map(|c| c.names.unwrap().get("en").unwrap().clone())
                .or(None);

            let p = json!({
                "type": "geoip",
                "ip": ip,
                "lat": loc.latitude,
                "lon": loc.longitude,
                "tz": loc.time_zone,
                "country": country.names?.get("en"),
                // "rep": rep.names,
                "city": city_name,
                "asn": asn.autonomous_system_organization,
            })
            .to_string();

            Some(p)
        }
        Err(e) => {
            println!("Can't parse ip {}, {}", ip, e);
            None
        }
    }
}
