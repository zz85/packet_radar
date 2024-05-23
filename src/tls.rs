use std::cmp;
use tls_parser::{parse_tls_extensions, TlsClientHelloContents, TlsExtension, TlsVersion};
use tls_parser::{TlsExtensionType, TlsServerHelloContents};

use itertools::Itertools;

use md5;

const JA3: bool = true;

// references
// https://github.com/rusticata/rusticata/blob/master/src/tls.rs

/// https://tools.ietf.org/html/draft-davidben-tls-grease-00
const GREASE_TABLE: &[u16] = &[
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa,
];

fn is_greased(val: &u16) -> bool {
    GREASE_TABLE.contains(val)
}

#[derive(Default, Debug)]
pub struct ClientHello {
    pub version: u16,
    pub sni: String,
    pub ja3: Option<String>,
    pub ja4: Option<String>,
}

pub fn process_client_hello(client_hello: tls_parser::TlsClientHelloContents<'_>) -> ClientHello {
    let mut info = ClientHello::default();
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
                            info.sni = std::str::from_utf8(b).unwrap_or("").to_owned();
                        }
                    }
                    TlsExtension::SupportedVersions(sv) => {
                        highest = highest_version(highest, sv);
                    }
                    _ => {}
                }
            }

            info.version = highest;

            if JA3 {
                let ja3 = build_ja3_fingerprint(&client_hello, &extensions);
                let digest = md5::compute(&ja3);
                let ja3_debug = format!("JA3: {} --> {:x}", ja3, digest);

                let (ja4, debug) = build_ja4_fingerprint(&client_hello, &extensions);
                let ja4_debug = format!("JA4: {ja4} {debug}");

                info.ja3 = Some(format!("{digest:x}"));
                info.ja4 = Some(ja4);
            }
        }
    }
    info
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
        if !is_greased(&version.0) {
            highest = cmp::max(highest, version.0);
        }
    }

    highest
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
        .filter(|x| !is_greased(x))
        .join("-");
    ja3.push_str(&ext_str);
    ja3.push(',');

    for ext in extensions {
        match ext {
            &TlsExtension::EllipticCurves(ref ec) => {
                ja3.push_str(&ec.iter().map(|x| x.0).filter(|x| !is_greased(x)).join("-"));
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

// See https://www.iana.org/assignments/tls-extensiontype-values/tls-extensiontype-values.xhtml#tls-extensiontype-values-1
const TLS_EXT_SERVER_NAME: u16 = 0; // Server Name Indication (SNI)
const TLS_EXT_ALPN: u16 = 16; // Application-Layer Protocol Negotiation (ALPN)
const TLS_EXT_SUPPORTED_VERSIONS: u16 = 43;
const TLS_EXT_QUIC_TRANSPORT_PARAMETERS: u16 = 57;

fn quic_marker(is_quic: bool) -> char {
    if is_quic {
        'q'
    } else {
        't'
    }
}

fn first_last(s: &str) -> (Option<char>, Option<char>) {
    let replace_nonascii_with_9 = |c: char| {
        if c.is_ascii() {
            c
        } else {
            '9'
        }
    };
    let mut chars = s.chars();
    let first = chars.next().map(replace_nonascii_with_9);
    let last = chars.next_back().map(replace_nonascii_with_9);
    (first, last)
}

/*/// Returns first 12 characters of the SHA-256 hash of the given string.
///
/// Returns `"000000000000"` (12 zeros) if the input string is empty.
 */

fn hash12(s: impl AsRef<str>) -> String {
    use sha2::{Digest as _, Sha256};

    let s = s.as_ref();
    if s.is_empty() {
        "000000000000".to_owned()
    } else {
        let sha256 = hex::encode(Sha256::digest(s));
        sha256[..12].into()
    }
}

pub fn build_ja4_fingerprint(
    client_hello: &TlsClientHelloContents,
    extensions: &Vec<TlsExtension>,
) -> (String, String) {
    let mut ciphers = client_hello
        .get_ciphers()
        .iter()
        .flat_map(|c| c.map(|a| a.id))
        .filter(|id| !is_greased(id))
        .collect::<Vec<_>>();
    ciphers.sort_unstable();

    let nr_ciphers = 99.min(ciphers.len());

    let ciphers = ciphers
        .iter()
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",");
    // println!("nr_ciphers: {nr_ciphers} {:?}", ciphers);

    let sig_algs = extensions
        .iter()
        .filter_map(|x| match x {
            TlsExtension::SignatureAlgorithms(sig_alg) => Some(
                sig_alg
                    .iter()
                    .map(|id| format!("{id:04x}"))
                    .collect::<Vec<_>>()
                    .join(","),
            ),
            _ => None,
        })
        .collect::<Vec<_>>();

    let default_string = "".to_owned();
    let sig_alg = sig_algs.first().unwrap_or(&default_string);
    let opt_underscore = if sig_algs.is_empty() { "" } else { "_" };

    // println!("{sig_alg:?}");

    let ext_ids = extensions
        .iter()
        .map(|x| TlsExtensionType::from(x).0)
        .filter(|x| !is_greased(x))
        .collect::<Vec<_>>();

    let quic = quic_marker(ext_ids.contains(&TLS_EXT_QUIC_TRANSPORT_PARAMETERS));
    let sni_marker = if ext_ids.contains(&TLS_EXT_SERVER_NAME) {
        'd'
    } else {
        'i'
    };

    let version = extensions
        .iter()
        .filter_map(|e| match e {
            TlsExtension::SupportedVersions(sv) => {
                let v = if sv.contains(&tls_parser::TlsVersion::Tls13) {
                    "13"
                } else if sv.contains(&tls_parser::TlsVersion::Tls12) {
                    "12"
                } else if sv.contains(&tls_parser::TlsVersion::Tls11) {
                    "11"
                } else if sv.contains(&tls_parser::TlsVersion::Tls10) {
                    "10"
                } else if sv.contains(&tls_parser::TlsVersion::Ssl30) {
                    "s3"
                } else if sv.contains(&tls_parser::TlsVersion::Tls13) {
                    // TODO QUICv1
                    "q1"
                } else {
                    "00"
                };
                // println!("{:?} -> {v}", sv);

                Some(v)
            }
            _ => None,
        })
        .take(1)
        .collect::<Vec<_>>();

    let tls_ver = "13";
    let tls_ver = version.first().unwrap_or(&"00");

    let alpn = extensions
        .iter()
        .filter_map(|e| {
            match e {
                TlsExtension::ALPN(alpn) => {
                    // println!("ALPN {:?}", alpn);
                    if let Some(s) = alpn.first() {
                        std::str::from_utf8(s).map(first_last).ok()
                    } else {
                        None
                    }

                    // count(&mut stats.extensions, "alpn".to_string());
                }
                _ => None,
            }
        })
        .take(1)
        .collect::<Vec<_>>();

    let alpn = alpn.first().unwrap_or(&(None, None));

    let nr_exts = 99.min(ext_ids.len());
    //     let nr_exts = 99.min(exts2.len());
    // "0610_1841c8e5b05d_54dd091a23e0": 25782  "0512_c96ac5133cd7_778a044fa4d6": 12404,

    let first_chunk = format!(
        "{quic}{tls_ver}{sni_marker}{nr_ciphers:02}{nr_exts:02}{alpn_0}{alpn_1}",
        alpn_0 = alpn.0.unwrap_or('0'),
        alpn_1 = alpn.1.unwrap_or('0'),
    );

    let mut ext_ids = ext_ids
        .iter()
        .filter(|x| **x != TLS_EXT_SERVER_NAME && **x != TLS_EXT_ALPN)
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>();

    ext_ids.sort_unstable();

    // println!("{ext_ids:?} nr_exts: {nr_exts} -> {}", ext_ids.len());

    let ciphers_hash = hash12(&ciphers);

    let exts = ext_ids.join(",");
    let part3 = format!("{exts}{opt_underscore}{sig_alg}");
    let exts_hash = hash12(&part3);

    let sig = format!("{first_chunk}_{ciphers_hash}_{exts_hash}");
    let debug = format!("{ciphers} {part3}");

    (sig, debug)
}
