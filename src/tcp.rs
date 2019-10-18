use tls_parser::{parse_tls_extensions, parse_tls_plaintext, TlsMessage, TlsMessageHandshake,
    TlsExtension, TlsVersion};
use std::collections::HashMap;
use std::sync::RwLock;

lazy_static! {
    pub static ref TCP_STATS: RwLock<TcpStats> = Default::default();
}

#[derive(Debug, Copy, Clone)]
pub struct ConnStat {
    client_tls_version: u8,
    server_tls_version: u8,
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
                server_tls_version: 0
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
            if stat.client_tls_version == 2 {
                client_12_count = client_12_count + 1;
            } else {
                client_13_count = client_13_count + 1;
            }
            if stat.server_tls_version == 2 {
                server_12_count = server_12_count + 1;
            } else {
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

                        let mut highest = 0; // client hello version

                        if client_hello.version == TlsVersion::Tls12 {
                            highest = 2;
                        }

                        client_hello.ext.map(|v| {
                            if let Ok((_, extensions)) = parse_tls_extensions(v) {
                                // println!("Client Hello Extensions {:?}", extensions);
                                // TlsExtension::SNI
                                // TlsExtension::EllipticCurves
                                // TlsExtension::ALPN
                                // TlsExtension::SignatureAlgorithms
                                // TlsExtension::KeyShare
                                // TlsExtension::SupportedVersions

                                // TODO write this in a functional way?
                                for ext in extensions {
                                    match ext {
                                        TlsExtension::SupportedVersions(sv) => {
                                            // println!("Client Hello Supported Version {:?}", sv);
                                            for version in sv {
                                                match version {
                                                    _Tls13 => {
                                                        highest = 3;
                                                    },
                                                    _Tls12 => {
                                                        if highest < 2 {
                                                            highest = 2
                                                        }
                                                    }
                                                    _ => {

                                                    }
                                                }
                                            }
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
                        conn.client_tls_version = highest;

                        tcp_stats.count();
                    }
                    TlsMessage::Handshake(TlsMessageHandshake::ServerHello(server_hello)) => {
                        // println!("Server Hello server_hello {:?}", server_hello);
                         let mut highest = 0; // client hello version

                        if server_hello.version == TlsVersion::Tls12 {
                            highest = 2;
                        }
                        server_hello.ext.map(|v| {
                            if let Ok((_, extensions)) = parse_tls_extensions(v) {
                                // TODO gather stats tls 1.3 usage
                                // println!("Server Hello Extensions {:?}", extensions);
                                // TlsExtension::PreSharedKey
                                // TlsExtension::KeyShare
                                // TlsExtension::SupportedVersions

                                 for ext in extensions {
                                    match ext {
                                        TlsExtension::SupportedVersions(sv) => {
                                            // println!("Server Hello Supported Version {:?}", sv);
                                            for version in sv {
                                                match version {
                                                    _Tls13 => {
                                                        highest = 3;
                                                    },
                                                    _Tls12 => {
                                                        if highest < 2 {
                                                            highest = 2
                                                        }
                                                    }
                                                    _ => {

                                                    }
                                                }
                                            }
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
