use std::{
    convert::TryFrom,
    io::Read,
    process::{Command, Stdio},
};

use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use std::fs::File;

use crossbeam::Sender;
use pnet::packet::ethernet::EthernetPacket;

use crate::{
    packet_capture::handle_ethernet_packet,
    structs::{PacketInfo, ProcInfo},
};
use std::io::{self};

const PCAPNG_PIB_NAME: u16 = 2; /* UTF-8 string with name of process */
const PCAPNG_PIB_PATH: u16 = 3; /* UTF-8 string with path of process */
const PCAPNG_PIB_UUID: u16 = 4; /* 16 bytes of the process UUID */
const PCAPNG_EPB_PIB_INDEX: u16 = 0x8001; /* 32 bits number of process information block within the section */

pub fn pcap_parse(path: &str, tx: Sender<PacketInfo>) {
    if path == "!" {
        println!("Spawning tcpdump");

        let mut process = Command::new("tcpdump")
            .arg("-k")
            .arg("-w")
            .arg("-")
            .stdout(Stdio::piped())
            .spawn()
            .expect("Failed to spawn child process");

        // Get the stdout handle
        let stdout = process
            .stdout
            .as_mut()
            .expect("Failed to get stdout handle");

        // let reader = BufReader::new(stdout);
        let mut reader = PcapNGReader::new(65536, stdout).expect("PcapNGReader");
        pcap_parse_with_reader(tx, &mut reader);
    } else if path == "-" {
        let stdin = io::stdin();
        let mut reader = PcapNGReader::new(65536, stdin).expect("PcapNGReader");
        pcap_parse_with_reader(tx, &mut reader);
    } else {
        let file = File::open(path).unwrap();
        let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
        pcap_parse_with_reader(tx, &mut reader);
    };
}

pub fn pcap_parse_with_reader<T: Read>(tx: Sender<PacketInfo>, reader: &mut PcapNGReader<T>) {
    let mut num_blocks = 0;

    let mut if_linktypes = Vec::new();
    let mut last_incomplete_index = 0;
    let mut process_block_info = Vec::new();

    loop {
        // std::thread::sleep(std::time::Duration::from_millis(10));
        match reader.next() {
            Ok((offset, block)) => {
                num_blocks += 1;
                match block {
                    PcapBlockOwned::NG(Block::ProcessInformation(ref proc)) => {
                        // println!("Proc block {proc:?}");

                        let mut info = ProcInfo::default();
                        info.pid = proc.process_id;

                        for option in &proc.options {
                            // println!("code: {} [{}]", option.code.0, option.len);

                            match option.code.0 {
                                PCAPNG_PIB_NAME => {
                                    // process name
                                    let name = std::str::from_utf8(option.value())
                                        .ok()
                                        .map(|v| v.trim_matches(char::from(0)).to_owned());
                                    info.name = name;
                                }
                                PCAPNG_PIB_PATH => {
                                    // process path
                                    // let value = std::str::from_utf8(option.value());
                                    // println!("{value:?}");
                                }
                                PCAPNG_PIB_UUID => {
                                    // 16 bytes uuid
                                    // println!("16 bytes value: {:?}", option.value());
                                }
                                0 => {
                                    // end
                                }
                                _ => {
                                    println!("unknown field: {:?}", option.value());
                                }
                            }
                        }

                        process_block_info.push(info);
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        // println!("SectionHeader {_shb:?}");
                        // starting a new section, clear known interfaces
                        if_linktypes = Vec::new();
                        process_block_info = Vec::new();
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        // println!("InterfaceDescription {idb:?}");
                        if_linktypes.push(idb.linktype);
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        // println!("enhanced packet {epb:?}");

                        let mut process = None;
                        for option in &epb.options {
                            if option.code.0 == PCAPNG_EPB_PIB_INDEX {
                                let pid = <[u8; 4]>::try_from(option.value())
                                    .ok()
                                    .map(u32::from_le_bytes);

                                // let pid = o.as_u32_le() // broken. see https://github.com/rusticata/pcap-parser/pull/39
                                let pid = pid.and_then(|i| process_block_info.get(i as usize));

                                process = pid;
                            }
                        }

                        assert!((epb.if_id as usize) < if_linktypes.len());
                        let linktype = if_linktypes[epb.if_id as usize];

                        let ether = EthernetPacket::new(&epb.data).unwrap();
                        // println!("pid: {process:?}");
                        handle_ethernet_packet(&ether, &tx, process);

                        // let res = pcap_parser::data::get_packetdata(
                        //     epb.data,
                        //     linktype,
                        //     epb.caplen as usize,
                        // );
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        // this is practical not used
                    }
                    PcapBlockOwned::NG(_) => {
                        // can be statistics (ISB), name resolution (NRB), etc.
                        eprintln!("unsupported block");
                    }
                    PcapBlockOwned::Legacy(_) | PcapBlockOwned::LegacyHeader(_) => unreachable!(),
                }
                reader.consume(offset);
            }
            Err(PcapError::Eof) => break,
            Err(PcapError::Incomplete(_)) => {
                if last_incomplete_index == num_blocks {
                    eprintln!("Could not read complete data block.");
                    eprintln!("Hint: the reader buffer size may be too small, or the input file nay be truncated.");
                    break;
                }
                last_incomplete_index = num_blocks;
                reader.refill().expect("Could not refill reader");
                continue;
            }
            Err(e) => panic!("error while reading: {:?}", e),
        }
    }
    println!("num_blocks: {}", num_blocks);
}

/*
   some interesting code for references
   https://github.com/rusticata/pcap-parser/pull/27
   https://github.com/asayers/pcarp/blob/master/src/block/epb.rs
   https://github.com/rusticata/pcap-analyzer/blob/master/libpcap-tools/src/data_engine.rs

   how apple pktap process information is stored in pcapng
     https://github.com/apple-opensource/libpcap/blob/dc199b42a8206254d1705d5612f7b26414252152/libpcap/pcap/pcap-ng.h#L342
     shows the IDs used for the process information section. how interests are
     PCAPNG_PIB_NAME - proc_info->proc_name
     PCAPNG_PIB_UUID - proc_info->proc_uuid

     pcap_ng_dump_proc_info
     https://github.com/apple-opensource/libpcap/blob/dc199b42a8206254d1705d5612f7b26414252152/libpcap/pcap-darwin.c#L737
     pcap_ng_dump_proc - responsible for writing the process info block
     pcap_ng_dump_pktap_v2 - dumps pktap
*/
