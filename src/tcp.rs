use tls_parser::{parse_tls_extensions, parse_tls_plaintext, TlsMessage, TlsMessageHandshake};

pub fn parse_tcp_payload(packet: &[u8]) {
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
                        println!("Version {}", client_hello.version);

                        client_hello.ext.map(|v| {
                            if let Ok((_, extensions)) = parse_tls_extensions(v) {
                                // println!("Client Hello Extensions {:?}", extensions);
                                // TlsExtension::SNI
                                // TlsExtension::EllipticCurves
                                // TlsExtension::ALPN
                                // TlsExtension::SignatureAlgorithms
                                // TlsExtension::KeyShare
                                // TlsExtension::SupportedVersions
                            }
                        });
                    }
                    TlsMessage::Handshake(TlsMessageHandshake::ServerHello(server_hello)) => {
                        // println!("Server Hello server_hello {:?}", server_hello);
                        server_hello.ext.map(|v| {
                            if let Ok((_, extensions)) = parse_tls_extensions(v) {
                                // TODO gather stats tls 1.3 usage
                                println!("Server Hello Extensions {:?}", extensions);
                                // TlsExtension::PreSharedKey
                                // TlsExtension::KeyShare
                                // TlsExtension::SupportedVersions
                            }
                        });
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
