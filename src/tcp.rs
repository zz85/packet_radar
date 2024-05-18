use std::collections::HashMap;
use std::sync::RwLock;
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsRecordType, TlsVersion};

use std::time::{Duration, Instant};

lazy_static! {
    pub static ref TCP_STATS: RwLock<TcpStats> = Default::default();
}

const TLS_STATS: bool = false;

use super::tls::{process_client_hello, process_server_hello};

#[derive(Debug, Copy, Clone)]
pub struct ConnStat {
    client_tls_version: u16,
    client_time: Instant,
    server_tls_version: u16,
    server_time: Instant,
    time_to_application_data: Duration,
}

#[derive(Debug, Clone)]
pub struct TcpStats {
    conn_map: HashMap<String, ConnStat>,
}

impl Default for TcpStats {
    fn default() -> TcpStats {
        TcpStats::new()
    }
}

impl TcpStats {
    pub fn new() -> Self {
        Self {
            conn_map: Default::default(),
        }
    }

    pub fn get_or_create_conn(&mut self, key: String) -> Option<&mut ConnStat> {
        if !self.conn_map.contains_key(&key) {
            let stat = ConnStat {
                client_tls_version: 0,
                server_tls_version: 0,
                client_time: Instant::now(),
                server_time: Instant::now(),
                time_to_application_data: Duration::new(0, 0),
            };

            self.conn_map.insert(key.clone(), stat);
        }

        self.conn_map.get_mut(&key)
    }

    pub fn count(&mut self) {
        if !TLS_STATS {
            return;
        }

        let map = &self.conn_map;
        let len = map.keys().len();

        let mut client_12_count = 0;
        let mut client_13_count = 0;
        let mut server_12_count = 0;
        let mut server_13_count = 0;
        let mut total_12_duration = Duration::new(0, 0);
        let mut total_13_duration = Duration::new(0, 0);

        for stat in map.values() {
            if stat.client_tls_version == TlsVersion::Tls12.0 {
                client_12_count += 1;
            } else if stat.client_tls_version == TlsVersion::Tls13.0 {
                client_13_count += 1;
            }

            if stat.server_tls_version == TlsVersion::Tls12.0 {
                server_12_count += 1;
                let lapsed = stat.server_time.duration_since(stat.client_time);
                // total_12_duration += lapsed;
                total_12_duration += stat.time_to_application_data;
            } else if stat.server_tls_version == TlsVersion::Tls13.0 {
                server_13_count += 1;
                let lapsed = stat.server_time.duration_since(stat.client_time);
                // total_13_duration += lapsed;
                total_13_duration += stat.time_to_application_data;
            }
        }

        if len % 1 == 0 {
            println!("TLS Total: {}", len);
            println!("Client TLS 1.2: {}", client_12_count);
            println!("Client TLS 1.3: {}", client_13_count);
            println!("Server TLS 1.2: {}", server_12_count);
            println!("Server TLS 1.3: {}", server_13_count);

            if server_12_count > 0 {
                println!("Avg RTT 1.2: {:?}", total_12_duration / server_12_count)
            };
            if server_13_count > 0 {
                println!("Avg RTT 1.3: {:?}", total_13_duration / server_13_count)
            };
        }
    }
}

pub fn parse_tcp_payload(packet: &[u8], key: &str) -> Option<()> {
    // if packet.len() > 4 {
    //     if packet[0] == 0x17 {
    //         return;
    //     }
    //     println!(
    //         "packet {:x} {:x} {:x} {:x}",
    //         packet[0], packet[1], packet[2], packet[3]
    //     );
    //     // 17 3 3 0 Application Data, TLS 1.2
    // }

    // TODO skip to the end of TCP header

    let v = parse_tls_plaintext(&packet)
        .map_err(|e| {
            // cannot parse
            e
        })
        .ok()?;

    // println!("TLS parsed {:?}", v);
    let (_, plain_text) = v;
    for m in plain_text.msg {
        // println!("msg {:?}", m);
        // Handshake(ClientKeyExchange)
        // Alert(TlsMessageAlert
        // Handshake(ClientHello(TlsClientHelloContents

        match m {
            TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) => {
                let highest = process_client_hello(client_hello);

                // get connection
                let mut tcp_stats = TCP_STATS.write().unwrap();
                let conn = tcp_stats.get_or_create_conn(key.to_owned()).unwrap();
                conn.client_tls_version = highest;
                conn.client_time = Instant::now();

                println!("Client Hello Version {} - {}", key, TlsVersion(highest));

                tcp_stats.count();
            }
            TlsMessage::Handshake(TlsMessageHandshake::ServerHello(server_hello)) => {
                let highest = process_server_hello(server_hello);

                // get connection
                let mut tcp_stats = TCP_STATS.write().unwrap();
                let conn = tcp_stats.get_or_create_conn(key.to_owned()).unwrap();
                conn.server_tls_version = highest;
                conn.server_time = Instant::now();
                println!(
                    "Server Hello Supported Version {} - {}",
                    key,
                    TlsVersion(highest)
                );
                println!("{:?}", conn.server_time.duration_since(conn.client_time));

                tcp_stats.count();
            }
            TlsMessage::ChangeCipherSpec => {
                // For TLS 1.2, usually marks encrypted messages after.
            }
            TlsMessage::Handshake(msg) => {
                // println!("Handshake msg {:?}", msg);
            }

            _ => {}
        }
    }

    if plain_text.hdr.record_type == TlsRecordType::ApplicationData {
        // println!("Application Data {:?}", app_data);
        let mut tcp_stats = TCP_STATS.write().unwrap();
        let conn = tcp_stats.get_or_create_conn(key.to_owned()).unwrap();
        if conn.time_to_application_data == Duration::new(0, 0)
                        // TODO filter that we cannot fetch tcp stat, right now just a heuristic
                        && Instant::now().duration_since(conn.client_time) > Duration::from_millis(1)
        {
            conn.time_to_application_data = Instant::now().duration_since(conn.client_time);
            // time to first application data or more commonly time to first byte
            println!(
                "Time to first byte: {}",
                conn.time_to_application_data.as_millis()
            );
            tcp_stats.count();
        }
    }

    Some(())
}
