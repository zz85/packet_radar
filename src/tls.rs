use std::cmp;
use tls_parser::{parse_tls_extensions, TlsExtension, TlsVersion};

use itertools::Itertools;

use md5;

use tls_parser::tls::*;
use tls_parser::tls_extensions::*;

const JA3: bool = true;

// references
// https://github.com/rusticata/rusticata/blob/master/src/tls.rs

/// https://tools.ietf.org/html/draft-davidben-tls-grease-00
const GREASE_TABLE: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

pub fn process_client_hello(client_hello: tls_parser::TlsClientHelloContents<'_>) -> u16 {
    let mut highest = client_hello.version.0;

    if let Some(v) = client_hello.ext {
        if let Ok((_, ref extensions)) = parse_tls_extensions(v) {
            // println!("Client Hello Extensions {:?}", extensions);
            // TlsExtension::EllipticCurves
            // TlsExtension::ALPN
            // TlsExtension::SignatureAlgorithms
            // TlsExtension::KeyShare
            // TlsExtension::PreSharedKey

            for ext in extensions {
                match ext {
                    TlsExtension::SNI(sni) => {
                        for (_, b) in sni {
                            println!("Sni: {}", std::str::from_utf8(b).unwrap_or(""));
                        }
                    }
                    TlsExtension::SupportedVersions(sv) => {
                        highest = highest_version(highest, sv);
                    }
                    _ => {}
                }
            }

            if JA3 {
                let ja3 = build_ja3_fingerprint(&client_hello, &extensions);
                let digest = md5::compute(&ja3);
                println!("JA3: {} --> {:x}", ja3, digest);
            }
        }
    }
    highest
}

pub fn process_server_hello(server_hello: tls_parser::TlsServerHelloContents<'_>) -> u16 {
    let mut highest = server_hello.version.0;
    if let Some(v) = server_hello.ext {
        if let Ok((_, ref extensions)) = parse_tls_extensions(v) {
            // println!("Server Hello Extensions {:?}", extensions);
            // TlsExtension::KeyShare count
            // Hello Retry stats
            // CipherSuit, ALPN
            // OCSP, Key Exchange

            for ext in extensions {
                match ext {
                    TlsExtension::SupportedVersions(sv) => {
                        highest = highest_version(highest, sv);
                        if highest < TlsVersion::Tls13.0 {
                            println!("************** DOWNGRADE ************???");
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    highest
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

fn is_tls13(_content: &TlsServerHelloContents, extensions: &Vec<TlsExtension>) -> bool {
    // look extensions, find the TlsSupportedVersion
    extensions
        .iter()
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

/// SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
pub fn build_ja3_fingerprint(
    content: &TlsClientHelloContents,
    extensions: &Vec<TlsExtension>,
) -> String {
    let mut ja3 = format!("{},", u16::from(content.version));

    let ciphers = content.ciphers.iter().join("-");
    ja3.push_str(&ciphers);
    ja3.push(',');

    let ext_str = extensions
        .iter()
        .map(|x| TlsExtensionType::from(x))
        .map(|x| u16::from(x))
        .filter(|x| !(GREASE_TABLE.iter().any(|g| g == x)))
        .join("-");
    ja3.push_str(&ext_str);
    ja3.push(',');

    for ext in extensions {
        match ext {
            &TlsExtension::EllipticCurves(ref ec) => {
                ja3.push_str(
                    &ec.iter()
                        .map(|x| x.0)
                        .filter(|x| !(GREASE_TABLE.iter().any(|g| g == x)))
                        .join("-"),
                );
            }
            _ => (),
        }
    }
    ja3.push(',');

    for ext in extensions {
        match ext {
            &TlsExtension::EcPointFormats(ref pf) => {
                ja3.push_str(&pf.iter().join("-"));
            }
            _ => (),
        }
    }

    ja3
}
