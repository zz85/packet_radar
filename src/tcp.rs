use dashmap::{
    mapref::one::{Ref, RefMut},
    DashMap,
};
use lazy_static::lazy_static;
use std::time::{Duration, Instant};
use tls_parser::{parse_tls_plaintext, TlsMessage, TlsMessageHandshake, TlsRecordType, TlsVersion};
use tracing::{info, trace};

lazy_static! {
    /// This is currently just TLS connections
    pub static ref TCP_STATS: TcpStats = Default::default();
}

const TLS_STATS: bool = false;

use super::tls::{process_client_hello, process_server_hello};

// IP Fragmentation
// https://en.wikipedia.org/wiki/IP_fragmentation
// https://tools.ietf.org/html/rfc791
// https://tools.ietf.org/html/rfc815
// https://packetpushers.net/ip-fragmentation-in-detail/

#[derive(Debug, Clone, Default)]
pub struct ConnStat {
    /// Highest client version
    client_tls_version: u16,
    /// Client Hello time
    pub client_time: Option<Instant>,
    /// Highest server version
    server_tls_version: u16,
    /// Server Hello time
    pub server_time: Option<Instant>,

    time_to_application_data: Duration,

    // from client hello
    pub sni: Option<String>,
    pub ja3: Option<String>,
    pub ja4: Option<String>,

    pub pid: Option<u32>,
    pub process_name: Option<String>,
    // TODO combine ConnectionMeta
    // associate dns quries
    // socket info
    pub pending: Option<Vec<u8>>,
}

#[derive(Debug, Clone)]
pub struct TcpStats {
    pub conn_map: DashMap<String, ConnStat>,
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

    pub fn get<'a>(&'a self, key: &String) -> Option<Ref<'a, String, ConnStat>> {
        self.conn_map.get(key)
    }

    pub fn get_or_create_conn<'a>(&'a self, key: String) -> RefMut<'a, String, ConnStat> {
        let entry = self.conn_map.entry(key).or_insert_with(|| ConnStat {
            client_tls_version: 0,
            server_tls_version: 0,
            client_time: Some(Instant::now()),
            server_time: Some(Instant::now()),
            time_to_application_data: Duration::new(0, 0),
            sni: None,
            ja3: None,
            ja4: None,
            ..Default::default()
        });

        entry
    }

    pub fn count(&self) {
        if !TLS_STATS {
            return;
        }

        let map = &self.conn_map;
        let len = map.len();

        let mut client_12_count = 0;
        let mut client_13_count = 0;
        let mut server_12_count = 0;
        let mut server_13_count = 0;
        let mut total_12_duration = Duration::new(0, 0);
        let mut total_13_duration = Duration::new(0, 0);

        for stat in map.iter() {
            let stat = stat.value();
            if stat.client_tls_version == TlsVersion::Tls12.0 {
                client_12_count += 1;
            } else if stat.client_tls_version == TlsVersion::Tls13.0 {
                client_13_count += 1;
            }

            if stat.server_tls_version == TlsVersion::Tls12.0 {
                server_12_count += 1;
                match (stat.server_time, stat.client_time) {
                    (Some(server_time), Some(client_time)) => {
                        let lapsed = server_time.duration_since(client_time);
                        // total_12_duration += lapsed;
                        total_12_duration += stat.time_to_application_data;
                    }
                    _ => {}
                }
            } else if stat.server_tls_version == TlsVersion::Tls13.0 {
                server_13_count += 1;
                match (stat.server_time, stat.client_time) {
                    (Some(server_time), Some(client_time)) => {
                        let lapsed = server_time.duration_since(client_time);
                        total_13_duration += stat.time_to_application_data;
                    }
                    _ => {}
                }
            }
        }

        if len % 1 == 0 {
            info!("TLS Total: {}", len);
            info!("Client TLS 1.2: {}", client_12_count);
            info!("Client TLS 1.3: {}", client_13_count);
            info!("Server TLS 1.2: {}", server_12_count);
            info!("Server TLS 1.3: {}", server_13_count);

            if server_12_count > 0 {
                info!("Avg RTT 1.2: {:?}", total_12_duration / server_12_count)
            };
            if server_13_count > 0 {
                info!("Avg RTT 1.3: {:?}", total_13_duration / server_13_count)
            };
        }
    }
}

pub fn is_handshake_packet(packet: &[u8]) -> bool {
    packet.len() > 4 // heuristics - byte 1 for TLS, 2..3 version, 4..5 version
    && packet[0] == 0x16
    && packet[1] == 0x03
}

pub fn parse_tcp_payload(packet: &[u8], key: &str) -> Option<ConnStat> {
    if !is_handshake_packet(packet) {
        return None;
    }
    // if packet.len() > 4 {
    //     if packet[0] == 0x17 {
    //         return;
    //     }
    //     info!(
    //         "packet {:x} {:x} {:x} {:x}",
    //         packet[0], packet[1], packet[2], packet[3]
    //     );
    //     // 17 3 3 0 Application Data, TLS 1.2
    // }

    // info!("CH: {:0x?}", packet);
    trace!("TLS payload: {} bytes", packet.len());

    let v = parse_tls_plaintext(&packet)
        .map_err(|e| {
            info!("Cannot parse {e:?}");
            // cannot parse
            e
        })
        .ok()?;

    // info!("TLS parsed {:?}", v);
    let (_, plain_text) = v;
    for m in plain_text.msg {
        // info!("msg {:?}", m);
        // Handshake(ClientKeyExchange)
        // Alert(TlsMessageAlert

        match m {
            TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) => {
                let ch = process_client_hello(client_hello);

                // get connection
                let tcp_stats = &TCP_STATS;
                let mut conn = tcp_stats.get_or_create_conn(key.to_owned());
                conn.client_tls_version = ch.version;
                conn.client_time = Some(Instant::now());

                trace!(
                    "Client Hello Version {} - {} - {:?}",
                    key,
                    TlsVersion(ch.version),
                    ch
                );
                conn.ja3 = ch.ja3;
                conn.ja4 = ch.ja4;
                conn.sni = Some(ch.sni);

                tcp_stats.count();
                return Some(conn.clone());
            }
            TlsMessage::Handshake(TlsMessageHandshake::ServerHello(server_hello)) => {
                let highest = process_server_hello(server_hello);

                // get connection
                let tcp_stats = &TCP_STATS;
                let mut conn = tcp_stats.get_or_create_conn(key.to_owned());
                conn.server_tls_version = highest;
                conn.server_time = Some(Instant::now());
                trace!(
                    "Server Hello Supported Version {} - {}",
                    key,
                    TlsVersion(highest)
                );
                trace!(
                    "Client -> Server Hello time: {:?}",
                    conn.server_time
                        .unwrap()
                        .duration_since(conn.client_time.unwrap())
                );

                tcp_stats.count();
                return Some(conn.clone());
            }
            TlsMessage::ChangeCipherSpec => {
                // For TLS 1.2, usually marks encrypted messages after.
            }
            TlsMessage::Handshake(msg) => {
                // info!("Handshake msg {:?}", msg);
            }

            _ => {}
        }
    }

    if plain_text.hdr.record_type == TlsRecordType::ApplicationData {
        // info!("Application Data {:?}", app_data);
        let tcp_stats = &TCP_STATS;
        let mut conn = tcp_stats.get_or_create_conn(key.to_owned());

        if conn.time_to_application_data == Duration::new(0, 0)
        // TODO probably need to check outgoing app data vs incoming app data
        // && Instant::now().duration_since(conn.client_time) > Duration::from_millis(1)
        {
            conn.time_to_application_data =
                Instant::now().duration_since(conn.client_time.unwrap());
            // time to first application data or more commonly time to first byte
            info!(
                "Time to first byte: {}",
                conn.time_to_application_data.as_millis()
            );
            tcp_stats.count();
        }
    }

    None
}
