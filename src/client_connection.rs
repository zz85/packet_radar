use websocket::server::WsServer;
use websocket::sender::Writer;
use websocket::message::OwnedMessage;

use std::sync::{Arc, RwLock};
use std::thread;
use std::net::TcpStream;

use serde_json::json;

use super::{PacketInfo, ClientRequest};
use super::{parse_dns, reverse_lookup};
use super::traceroute;
use super::{city_lookup, asn_lookup};

pub fn handle_clients(server: WsServer<websocket::server::NoTlsAcceptor, std::net::TcpListener>, clients: Arc<RwLock<Vec<Writer<TcpStream>>>>) {
    for connection in server.filter_map(Result::ok) {
        let clients = clients.clone();

        thread::spawn(move || {
            let ws = connection.accept().unwrap();
            let ip = ws.peer_addr().unwrap();
            let (mut rx, mut _tx) = ws.split().unwrap();

            // add writer stream to shared vec
            clients.write().unwrap().push(_tx);

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
                            },
                        };

                        let req = data.req;
                        // println!("data req: {}, val: {}", req, data.value);

                        match req.as_ref() {
                            "lookup" => {
                                // handle look up address
                                let ip = data.value;
                                let hostname = reverse_lookup(ip.clone());
                                // println!("Name look up from: {} to {}", destination, hostname);

                                let p = json!({
                                    "type": "lookup_addr",
                                    "ip": ip,
                                    "hostname": hostname,
                                })
                                .to_string();

                                broadcast(clients.clone(), p);
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

                                        broadcast(clients.clone(), p);
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
                            },
                            "geoip" => {
                                let ip = data.value;
                                // if let Some(r) = get_geo_ip(ip) {
                                //     broadcast(clients.clone(), r);
                                // };

                                match get_geo_ip(ip) {
                                    Some(r) => broadcast(clients.clone(), r),
                                    None => { println!("FAIL") }
                                };
                            }
                            _ => {}
                        }

                        // handle filtering
                        // handle get buffers
                    }
                    OwnedMessage::Binary(buf) => {}
                    others => {
                        println!("ok {:?}", others);
                    }
                }
            }
        });
    }
}

fn broadcast(clients: Arc<RwLock<Vec<Writer<TcpStream>>>>, text:String) {
    println!("Broadcasting... {}", text);
    let message = OwnedMessage::Text(text);
    clients
        .write()
        .unwrap()
        .drain_filter(|c| c.send_message(&message).is_err());
}

fn get_geo_ip(ip:String) -> Option<String> {
    println!("Geo Ip {}", ip);
    match ip.parse() {
        Ok(addr) => {
            let city = match city_lookup(addr) {
                Ok(city) => city,
                Err(e) => {
                    println!("Cant look up {:?}", e);
                    return None
                }
            };
            let asn = match asn_lookup(addr) {
                Ok(asn) => asn,
                Err(e) => {
                    println!("Cant look up {:?}", e);
                    return None
                }
            };
            println!("City {:?}", city);
            println!("Asn {:?}", asn);

            let loc = city.location?;
            let country = city.registered_country?;
            // let rep = city.represented_country?;

            // let city_names = match city.city {
            //     Some(city) => {
            //         let city = city;
            //         let names = city.names;
            //         let name = names?.get("en");
            //         name
            //     },
            //     None => None
            // };

            let p = json!({
                "type": "geoip",
                "ip": ip,
                "lat": loc.latitude,
                "lon": loc.longitude,
                "tz": loc.time_zone,
                "country": country.names?.get("en"),
                // "rep": rep.names,
                // "city": city_names,
                "asn": asn.autonomous_system_organization,
            }).to_string();

            Some(p)
        }
        Err(e) => {
            println!("Can't parse ip {}, {}", ip, e);
            None
        }
    }
}