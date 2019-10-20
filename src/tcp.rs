use tls_parser::{parse_tls_extensions, parse_tls_plaintext, TlsMessage, TlsMessageHandshake,
    TlsExtension, TlsVersion};
use std::collections::HashMap;
use std::sync::RwLock;
use std::cmp;

use itertools::Itertools;

use std::time::Instant;

use md5;

use tls_parser::tls::*;
use tls_parser::tls_alert::{TlsAlertDescription, TlsAlertSeverity};
use tls_parser::tls_ciphers::*;
use tls_parser::tls_dh::*;
use tls_parser::tls_ec::*;
use tls_parser::tls_extensions::*;
use tls_parser::tls_sign_hash::*;
use tls_parser::tls_states::{TlsState,tls_state_transition};

lazy_static! {
    pub static ref TCP_STATS: RwLock<TcpStats> = Default::default();
}

#[derive(Debug, Copy, Clone)]
pub struct ConnStat {
    client_tls_version: u16,
    client_time: Instant,
    server_tls_version: u16,
    server_time: Instant,
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
            };

            self.conn_map.insert(key.clone(), stat);
        }

        self.conn_map.get_mut(&key)
    }

    pub fn count(&mut self) {
        let map = self.conn_map.clone();
        let len = map.keys().len();

        let mut client_12_count = 0;
        let mut client_13_count = 0;
        let mut server_12_count = 0;
        let mut server_13_count = 0;

        for stat in map.values() {
            if stat.client_tls_version == TlsVersion::Tls12.0 {
                client_12_count = client_12_count + 1;
            } else if stat.client_tls_version == TlsVersion::Tls13.0 {
                client_13_count = client_13_count + 1;
            }
            if stat.server_tls_version == TlsVersion::Tls12.0 {
                server_12_count = server_12_count + 1;
            } else if stat.server_tls_version == TlsVersion::Tls13.0 {
                server_13_count = server_13_count + 1;
            }
        }

        if len % 1 == 0 {
            println!("TLS Total: {}", len);
            println!("Client TLS 1.2: {}", client_12_count);
            println!("Client TLS 1.3: {}", client_13_count);
            println!("server TLS 1.2: {}", server_12_count);
            println!("server TLS 1.3: {}", server_13_count);
        }
    }
}

pub fn parse_tcp_payload(packet: &[u8], key: &str) {
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

    let r = parse_tls_plaintext(&packet);
    match r {
        Ok(v) => {
            // println!("TLS parsed {:?}", v);

            let (_, plain_text) = v;
            // let record_header = raw_record.hdr;
            for m in plain_text.msg {
                // println!("msg {:?}", m);
                // Handshake(ClientKeyExchange)
                // Alert(TlsMessageAlert
                // Handshake(ClientHello(TlsClientHelloContents

                match m {
                    TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) => {
                        // println!("Client Hello client_hello {:?}", client_hello);
                        // ciphers
                        // println!("Client Hello Version {}", client_hello.version);

                        let mut highest = client_hello.version.0;

                        client_hello.ext.map(|v| {
                            if let Ok((_, ref extensions)) = parse_tls_extensions(v) {
                                // println!("Client Hello Extensions {:?}", extensions);
                                // TlsExtension::SNI
                                // TlsExtension::EllipticCurves
                                // TlsExtension::ALPN
                                // TlsExtension::SignatureAlgorithms
                                // TlsExtension::KeyShare

                                // TODO write this in a functional way?
                                for ext in extensions {
                                    match ext {
                                        TlsExtension::SNI(sni) => {
                                            for (_, b) in sni {
                                                println!("Sni: {}", std::str::from_utf8(b).unwrap_or(""));
                                            }
                                        }
                                        TlsExtension::SupportedVersions(sv) => {
                                            highest = highest_version(highest, sv);
                                        },
                                        _ => {

                                        }
                                    }

                                }

                                let ja3 = build_ja3_fingerprint(&client_hello, &extensions);
                                let digest = md5::compute(&ja3);
                                println!("JA3: {} --> {:x}", ja3, digest);
                            }
                        });

                        // get connection
                        let mut tcp_stats = TCP_STATS.write().unwrap();
                        let conn = tcp_stats.get_or_create_conn(key.to_owned()).unwrap();
                        conn.client_tls_version = highest;
                        conn.client_time = Instant::now();

                        println!("Client Hello Version {} - {}", key, TlsVersion(highest));


                        tcp_stats.count();
                    }
                    TlsMessage::Handshake(TlsMessageHandshake::ServerHello(server_hello)) => {
                        // println!("Server Hello server_hello {:?}", server_hello);

                        let mut highest = server_hello.version.0;
                        server_hello.ext.map(|v| {
                            if let Ok((_, ref extensions)) = parse_tls_extensions(v) {
                                // TODO gather stats tls 1.3 usage
                                // println!("Server Hello Extensions {:?}", extensions);
                                // TlsExtension::PreSharedKey
                                // TlsExtension::KeyShare

                                 for ext in extensions {
                                    match ext {
                                        TlsExtension::SupportedVersions(sv) => {
                                            highest = highest_version(highest, sv);
                                        },
                                        _ => {
                                        }
                                    }
                                }


                            }
                        });

                        // get connection
                        let mut tcp_stats = TCP_STATS.write().unwrap();
                        let conn = tcp_stats.get_or_create_conn(key.to_owned()).unwrap();
                        conn.server_tls_version = highest;
                        conn.server_time = Instant::now();
                        println!("Server Hello Supported Version {} - {}", key, TlsVersion(highest));
                        println!("{:?}", conn.server_time.duration_since(conn.client_time));

                        tcp_stats.count();
                    }
                    TlsMessage::Handshake(msg) => {
                        // println!("Handshake msg {:?}", msg);
                    }
                    _ => {}
                }
            }
        }
        _ => {
            // println!("Not TLS {:?}", e)
        }
    }
}

fn highest_version(highest: u16, versions: &Vec<TlsVersion>) -> u16 {
    let mut highest = highest;

    for version in versions {
        if !(GREASE_TABLE.iter().any(|g| g == &version.0)) {
            highest = cmp::max(highest, version.0);
        }
    }

    highest
}

// from https://github.com/rusticata/rusticata/blob/master/src/tls.rs

/// https://tools.ietf.org/html/draft-davidben-tls-grease-00
const GREASE_TABLE : &[u16] = &[
    0x0a0a,
    0x1a1a,
    0x2a2a,
    0x3a3a,
    0x4a4a,
    0x5a5a,
    0x6a6a,
    0x7a7a,
    0x8a8a,
    0x9a9a,
    0xaaaa,
    0xbaba,
    0xcaca,
    0xdada,
    0xeaea,
    0xfafa
];


/// SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
pub fn build_ja3_fingerprint(content: &TlsClientHelloContents, extensions: &Vec<TlsExtension>) -> String {
    let mut ja3 = format!("{},",u16::from(content.version));

    let ciphers = content.ciphers.iter().join("-");
    ja3.push_str(&ciphers);
    ja3.push(',');

    let ext_str = extensions.iter()
        .map(|x| TlsExtensionType::from(x))
        .map(|x| u16::from(x))
        .filter(|x| !(GREASE_TABLE.iter().any(|g| g == x)))
        .join("-");
    ja3.push_str(&ext_str);
    ja3.push(',');

    for ext in extensions {
        match ext {
            &TlsExtension::EllipticCurves(ref ec) => {
                ja3.push_str(&ec.iter()
                             .map(|x| x.0)
                             .filter(|x| !(GREASE_TABLE.iter().any(|g| g == x)))
                             .join("-"));
            },
            _ => (),
        }
    }
    ja3.push(',');

    for ext in extensions {
        match ext {
            &TlsExtension::EcPointFormats(ref pf) => {
                ja3.push_str(&pf.iter().join("-"));
            },
            _ => (),
        }
    }

    ja3
}

fn is_tls13(_content: &TlsServerHelloContents, extensions: &Vec<TlsExtension>) -> bool {
    // look extensions, find the TlsSupportedVersion
    extensions.iter()
        .find(|&ext| TlsExtensionType::SupportedVersions == ext.into())
        .map(|ref ext| {
            if let TlsExtension::SupportedVersions(ref versions) = ext {
                versions.len() == 1 && versions[0] == TlsVersion::Tls13
            } else {
                false
            }
        })
        .unwrap_or(false)
}

