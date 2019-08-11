use std::fmt;
use zerocopy::{FromBytes, AsBytes, Unaligned, ByteSlice, LayoutVerified};

use std::net::IpAddr;
use std::char;
use dns_lookup::lookup_addr;

use std::collections::HashMap;


// static mut cached_ips_to_domain = HashMap::new();

pub fn parse_dns(payload: &[u8]) -> Option<DnsPacket<&[u8]>> {
    DnsPacket::parse(payload)
}

pub fn reverse_lookup(ip: String) -> String {
    sys_lookup(ip)
}

fn sys_lookup(ip: String) -> String {
    let hostname = lookup_addr(&ip.parse::<IpAddr>().unwrap()).unwrap();
    hostname
}

#[derive(FromBytes, AsBytes, Unaligned)]
#[repr(C)]
struct DnsHeader {
    transaction_id: [u8; 2],
    dns_flags: [u8; 2],
        // QR: bool, // 1 query or reply
        // OPCODE:, // 4 QUERY (0) IQUERY (1), or STATUS (server status request, 2)
        // AA: bool, // 1,
        // RC: bool, /// trancation
    questions: [u8; 2],
    answers: [u8; 2],
    athority_rrs: [u8; 2],
    additional_rrs: [u8; 2],
        // query
        // name - read till 00 (todo: punny code encoding)
        // type: [2] a = 01
        // class: [2]

        // answer
        // name - 2byte
        // type
        // data len
        // address
}

pub struct DnsPacket <B> {
    header: LayoutVerified<B, DnsHeader>,
    body: B,
}

enum ParseDns {
    QuerySection,
    AnswerSection,
    REST
}

// TODO use FromPrimitive
#[derive(PartialEq)]
enum RecordTypes {
    A = 1,
    CNAME = 5,
    AAAA = 28, // IPV6
    UNKNOWN
}

impl RecordTypes {
    fn from_u16(i: u16) -> RecordTypes {
        match i {
            1 => RecordTypes::A,
            5 => RecordTypes::CNAME,
            28 => RecordTypes::AAAA,
            _ => RecordTypes::UNKNOWN
        }
    }
}

impl<B: ByteSlice> DnsPacket<B> {
    pub fn parse(bytes: B) -> Option<DnsPacket<B>> {
        let (header, body) = LayoutVerified::new_unaligned_from_prefix(bytes)?;
        Some(DnsPacket { header, body })
    }

    pub fn answers(&self) -> u16 {
        (self.header.answers[1]).into()
    }

    pub fn is_reply(&self) -> bool  {
        self.header.transaction_id[0] >> 7 == 0
    }

    pub fn questions(&self) -> u16 {
        (self.header.questions[1]).into()
    }

    fn parse_name(&self, buf:&mut Buf) -> String {
        let mut domain = String::new();

        loop {
            let next = buf.read_u8();
            if next == 0 {
                domain.pop();
                break;
            };

            let s = buf.read_bytes(next as usize);
            domain.push_str(&String::from_utf8_lossy(s));
            domain.push('.');
        }

        println!("Parsed Domain {}", domain);

        domain
    }

    pub fn parse_body(&self) {
        let b = &self.body;

        let mut buf = Buf::new(b);
        let mut state = ParseDns::QuerySection;


        // Warning, not very safe parsing
        while buf.avail() {
            // println!("Buf avail");
            match state {
                ParseDns::QuerySection => {
                    let domain = self.parse_name(&mut buf);

                    // type
                    buf.read_16();

                    // class
                    buf.read_16();

                    state = ParseDns::AnswerSection;
                }

                ParseDns::AnswerSection => {
                    println!("DNS Answers");

                    for _ in 0..self.answers() {
                        if ((buf.peek_u8() >> 6) & 3) > 0 {
                            // hardcode domain compression assumption
                            buf.read_16();
                        } else {
                            println!("Do something here!");
                            self.parse_name(&mut buf);
                        }
                        // else read name again

                        let ans_type = RecordTypes::from_u16(buf.read_16());

                        // class
                        buf.read_16();

                        // ttl
                        buf.read_bytes(4);

                        // read data length
                        let space = buf.read_16() as usize;

                        let ip = buf.read_bytes(space);

                        match ans_type {
                            RecordTypes::A => {
                                // Address record

                                if space == 4 {
                                    let mut ip_str = String::new();

                                    for i in 0..space {
                                        ip_str.push_str(&ip[i].to_string());

                                        if i != space - 1 {
                                            ip_str.push('.');
                                        }
                                    }

                                    println!("joined - {}", ip_str);
                                }

                                println!("Got ip{} {:?}", space, ip);
                            }

                            RecordTypes::AAAA => {
                                // IP v6 Address record
                                let mut ip_str = String::new();
                                for i in 0.. space / 2 {

                                    let hex = ((ip[i * 2] as u16) << 8) + (ip[i * 2 + 1] as u16);

                                    ip_str.push_str(&format!("{:x}", hex));

                                    if i != (space / 2 - 1) {
                                        ip_str.push(':');
                                    }
                                }

                                println!("Got ipv6 AAAA {:?} - {}", space, ip_str);
                            }

                            RecordTypes::CNAME => {
                                // should do a modified name parsing
                                let cname = String::from_utf8_lossy(ip);
                                println!("CNAME {}", cname);
                            }

                            _ => {
                                println!("MEOW WRONG TYPE");
                            }
                        }
                    }
                    break;
                }

                _ => {
                    break;
                }
            }
        }
    }

     pub fn first_name(&self) -> String {
        let b = &self.body;
        let mut more = 0;
        let mut domain = String::new();
        for &v in b.iter() {
            if v == 0 {
                break
            };

            if more == 0 {
                more = v;
            }
            else {
                more -= 1;
                domain.push(v as char);

                if more == 0 {
                    domain.push('.');
                }
            }
        }

        domain.pop();
        domain.into()
    }
}

/* Simple ByteReader */
// TODO use byteorder or some other library?

struct Buf<'a> {
    buf: &'a [u8],
    pointer: usize
}

impl Buf <'_> {

    pub fn new(buf: &[u8]) -> Buf <'_> {
        Buf {
            buf: buf,
            pointer: 0
        }
    }

    fn read_u8(&mut self) -> u8 {
        let val = self.buf[self.pointer];
        self.pointer += 1;
        return val;
    }

    fn peek_u8(&mut self) -> u8 {
        let val = self.buf[self.pointer];
        return val;
    }

    fn read_16(&mut self) -> u16 {
        let val = ((self.buf[self.pointer] as u16) << 8) + (self.buf[self.pointer + 1] as u16);
        self.pointer += 2;
        return val;
    }

    fn read_bytes(&mut self, count: usize) -> &[u8] {
        let start = self.pointer;
        self.pointer = start + count;
        return &self.buf[start..self.pointer];
    }

    fn seek(&mut self, inc: usize) {
        self.pointer += inc;
    }

    fn avail(&mut self) -> bool {
        self.pointer < self.buf.len()
    }
}


impl fmt::Display for DnsPacket<&[u8]> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "is_reply: {},
         questions: {}, answers: {}
         first name: {}
         ", self.is_reply(), self.questions(), self.answers(), self.first_name())
    }
}