// https://quicwg.org/base-drafts/draft-ietf-quic-invariants.html
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-quic.c
// see dissect_quic()
// find_or_create_conversation

use bytes::Buf;
use hex_literal::hex;
use quick_cache::sync::Cache;
use ring::hkdf;
use std::io::Cursor;
use tls_parser::{parse_tls_message_handshake, TlsMessage, TlsMessageHandshake};
use tracing::{debug, info};

// should probably utilize this https://github.com/zz85/quic-initial-degreaser/blob/main/src/quic_initial_degreaser.rs
// since draft 29
pub const INITIAL_SALT_VALUE: [u8; 20] = hex!("afbfec289993d24c9e9786f19c6111e04390a899");
pub const INITIAL_CLIENT_LABEL: [u8; 9] = *b"client in";
pub const INITIAL_SERVER_LABEL: [u8; 9] = *b"server in";

lazy_static::lazy_static! {
    static ref INITIAL_SALT: hkdf::Salt = hkdf::Salt::new(hkdf::HKDF_SHA256, &INITIAL_SALT_VALUE);

    static ref QUIC_CACHE: Cache<Vec<u8>, CryptoAssembler> = Cache::new(50);
}

// https://quicwg.org/base-drafts/draft-ietf-quic-transport.html#sample-varint
fn read_var_int<B: Buf>(buf: &mut B) -> u64 {
    let mut v = buf.get_u8() as u64;

    let prefix = v >> 6;
    let length = 1 << prefix;

    v = v & 0x3f;
    for _ in 0..length - 1 {
        v = (v << 8) + buf.get_u8() as u64;
    }

    v
}

/* https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-initial-secrets */
// create initial decoders
fn calc_initial_secrets(connection_id: &[u8]) {
    let initial_secrets = INITIAL_SALT.extract(connection_id);

    let client_initial_secrets = initial_secrets
        .expand(&[&INITIAL_CLIENT_LABEL], INITIAL_SALT.algorithm())
        .expect("calc secrets");

    //     client_initial_secret = HKDF-Expand-Label(initial_secret,
    //         "client in", "",
    //         Hash.length)
    // server_initial_secret = HKDF-Expand-Label(initial_secret,
    //         "server in", "",
    //         Hash.length)
    /* Packet numbers are protected with AES128-CTR,
     * initial packets are protected with AEAD_AES_128_GCM. */
}

pub fn dissect(packet: &[u8]) -> Option<ClientHello> {
    return dissect2(packet);

    let mut view = Cursor::new(packet);

    let first_byte = view.get_u8();
    // https://godbolt.org/z/T8WT68
    let long_header = first_byte & 0b10000000 > 0;
    let fixed = first_byte & 0x40 > 0;

    // https://datatracker.ietf.org/doc/html/rfc9000#name-long-header-packets
    if long_header && fixed {
        let packet_type = (first_byte >> 4) & 0x3;
        let packet_number_len = (first_byte & 0x3) + 1;

        let packet_type_str = get_long_packet_type_str(packet_type);

        let version = view.get_u32();

        let version_str = get_version_str(version);
        debug!("{packet_type_str} {version_str}");

        let dcid_len = view.get_u8();
        if dcid_len > 20 {
            return None;
        }
        let dcid_buf = view.copy_to_bytes(dcid_len as usize);

        let scid_len = view.get_u8();
        if scid_len > 20 {
            return None;
        }
        let scid_buf = view.copy_to_bytes(scid_len as usize);

        if packet_type == 0 {
            let token_length = read_var_int(&mut view);
            if token_length != 0 {
                debug!("Bad token length");
            }

            let length = read_var_int(&mut view);

            // read packet number
            let packet_number = view.get_uint(packet_number_len as usize);
            // rest of payload

            // remove header protection

            // payload - client hello

            debug!(
                "QUIC packet length: {}, PN len: {}",
                length, packet_number_len
            );
            // https://quicwg.org/base-drafts/draft-ietf-quic-tls.html#name-header-protection-applicati
            // https://github.com/musec/rusty-shark
            // https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-quic.c
        }

        debug!(
            "QUIC Long header: {} quic-{} dcid: {:x} scid: {:x}",
            packet_type_str, version_str, dcid_buf, scid_buf
        );

        return None;
    }
    None
}

fn get_long_packet_type_str(long_type: u8) -> &'static str {
    match long_type {
        0x0 => "initial",
        0x1 => "0-rtt",
        0x2 => "handshake",
        0x3 => "retry",
        _ => "Err",
    }
}

fn get_version_str(version: u32) -> &'static str {
    match version {
        0x00000000 => "Version Negotiation",
        0x00000001 => "QUICv1",
        0x51303434 => "Google Q044",
        0x51303530 => "Google Q050",
        0x54303530 => "Google T050",
        0x54303531 => "Google T051",
        0xfaceb001 => "Facebook mvfst (draft-22)",
        0xfaceb002 => "Facebook mvfst (draft-27)",
        0xfaceb00e => "Facebook mvfst (Experimental)",
        0xff000004 => "draft-04",
        0xff000005 => "draft-05",
        0xff000006 => "draft-06",
        0xff000007 => "draft-07",
        0xff000008 => "draft-08",
        0xff000009 => "draft-09",
        0xff00000a => "draft-10",
        0xff00000b => "draft-11",
        0xff00000c => "draft-12",
        0xff00000d => "draft-13",
        0xff00000e => "draft-14",
        0xff00000f => "draft-15",
        0xff000010 => "draft-16",
        0xff000011 => "draft-17",
        0xff000012 => "draft-18",
        0xff000013 => "draft-19",
        0xff000014 => "draft-20",
        0xff000015 => "draft-21",
        0xff000016 => "draft-22",
        0xff000017 => "draft-23",
        0xff000018 => "draft-24",
        0xff000019 => "draft-25",
        0xff00001a => "draft-26",
        0xff00001b => "draft-27",
        0xff00001c => "draft-28",
        0xff00001d => "draft-29",
        0xff00001e => "draft-30",
        0xff00001f => "draft-31",
        0xff000020 => "draft-32",
        0xff000021 => "draft-33",
        0xff000022 => "draft-34",
        0xff020000 => "v2-draft-00",
        0x709A50C4 => "v2-draft-01",
        0x6b3343cf => "v2",
        version if (version & 0x0F0F0F0F) == 0x0a0a0a0a => "version negotiation",
        _ => "unknown version",
    }
}

fn should_parse(packet: &[u8]) -> bool {
    if packet.len() < 1 {
        return false;
    }

    let first_byte = packet[0];
    let long_header = first_byte & 0b10000000 > 0;
    let fixed = first_byte & 0x40 > 0;

    long_header && fixed
}

use s2n_codec::DecoderBufferMut;
use s2n_quic_core::{
    connection::id::ConnectionInfo,
    crypto::InitialKey,
    frame::{Crypto, Frame, FrameMut},
    inet::SocketAddress,
    packet::ProtectedPacket,
};

use crate::tls::{process_client_hello, ClientHello};

pub fn dissect2(packet: &[u8]) -> Option<ClientHello> {
    if !should_parse(packet) {
        return None;
    }

    let mut data = [0; 1500];
    let decode_buffer = &mut data[..packet.len()];
    decode_buffer.copy_from_slice(packet);

    let payload = DecoderBufferMut::new(decode_buffer);
    let remote_address = SocketAddress::default();
    let connection_info = ConnectionInfo::new(&remote_address);

    let (packet, _remaining) = ProtectedPacket::decode(payload, &connection_info, &0).ok()?;

    let version = packet.version()?;

    // care only about initial packets
    let protected_packet = match packet {
        ProtectedPacket::Initial(packet) => packet,
        _ => {
            return None;
        }
    };

    let (initial_key, initial_header_key) = s2n_quic_crypto::initial::InitialKey::new_server(
        protected_packet.destination_connection_id(),
    );

    let intial_encrypted = protected_packet
        .unprotect(&initial_header_key, Default::default())
        .map_err(|e| {
            debug!("cannot unprotect {e}");
        })
        .ok()?;

    let clear_initial = intial_encrypted
        .decrypt(&initial_key)
        .map_err(|err| {
            debug!("cannot decrypt {err}");
            // just move on if we can't decrypt packet
        })
        .ok()?;

    let packet_number = clear_initial.packet_number;
    let dcid = clear_initial.destination_connection_id().to_vec();
    let scid = clear_initial.source_connection_id().to_vec();

    debug!("QUIC Packet version {version}. #{packet_number}. scid {scid:02x?} -> dcid {dcid:02x?}");

    let mut payload = clear_initial.payload;
    let mut crypto = QUIC_CACHE.get(&dcid).unwrap_or(CryptoAssembler::new());

    // iterate frames from the QUIC packet
    while !payload.is_empty() {
        let (frame, remaining) = payload.decode::<FrameMut>().unwrap();
        if let Frame::Crypto(frame) = frame {
            // handle_crypto_frame
            crypto.add_frame(frame);
        }

        payload = remaining;
    }

    if crypto.completed() {
        QUIC_CACHE.remove(&dcid);
        let (_, msg) = parse_tls_message_handshake(crypto.get_bytes())
            .map_err(|e| info!("Cannot parse {e:?}"))
            .ok()?;

        if let TlsMessage::Handshake(TlsMessageHandshake::ClientHello(client_hello)) = msg {
            let ch = process_client_hello(client_hello);

            info!("QUIC {ch:?}");
            return Some(ch);
        }
    } else {
        QUIC_CACHE.insert(dcid, crypto);
    }

    None
}

/// we should probably use s2n_quic_core::buffer::Reassembler
/// as this is something simple, doesn't check duplicate bytes range
/// but could do for now
#[derive(Clone, Debug)]
struct CryptoAssembler {
    // up to 64k support
    crypto: [u8; 1 << 16],
    size: usize,
    recv: usize,
}

impl CryptoAssembler {
    fn new() -> Self {
        Self {
            crypto: [0u8; 1 << 16],
            size: 0,
            recv: 0,
        }
    }
    fn add_frame(&mut self, frame: Crypto<DecoderBufferMut>) {
        let slice = frame.data.as_less_safe_slice();
        let offset = frame.offset.as_u64() as usize;
        let to = offset + slice.len();

        debug!("received: {offset}..{to}");

        self.crypto[offset..to].copy_from_slice(slice);
        // let's expect the first 4 bytes to be together
        if offset == 0 && to > 2 {
            let target: u32 = ((self.crypto[1] as u32) << 16)
                + ((self.crypto[2] as u32) << 8)
                + self.crypto[3] as u32;
            self.size = target as usize + 4;
            debug!("matched 4 bytes {:x} - {target}", self.crypto[0]);
        }

        self.recv += slice.len();
    }

    fn get_bytes(&self) -> &[u8] {
        &self.crypto[..self.size]
    }

    fn completed(&self) -> bool {
        debug!("QUIC Crypto completed: {}/{}", self.recv, self.size);
        self.size > 0 && self.recv == self.size
    }
}
