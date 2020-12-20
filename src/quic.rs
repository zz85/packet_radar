
// https://quicwg.org/base-drafts/draft-ietf-quic-invariants.html
// https://github.com/wireshark/wireshark/blob/master/epan/dissectors/packet-quic.c
// see dissect_quic()

use std::io::Cursor;
use bytes::Buf;



pub fn dissect(packet: &[u8]) -> bool {
    let mut view = Cursor::new(packet);

    let first_byte = view.get_u8();
    // https://godbolt.org/z/T8WT68
    let long_header = first_byte & 0b10000000 > 0;
    let fixed = first_byte & 0x40 > 0;

    if long_header && fixed {
        let long_type = (first_byte >> 4) & 0x3;
        
        let long_type_str = match long_type {
            0x0 => "initia;",
            0x1 => "0-rtt",
            0x2 => "handshake",
            0x3 => "retry",
            _ => "Err"
        };

        let version = view.get_u32();

        let version_str = match version {
            0x00000000 => "Version Negotiation",
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
            _ => "unknown version",
        };

        println!("Long header: {} {}", long_type_str, version_str);
        return true;
    }

    /*
    0x0	Initial	Section 17.2.2
    0x1	0-RTT	Section 17.2.3
    0x2	Handshake	Section 17.2.4
    0x3	Retry	Section 17.2.5
    */
    false
}