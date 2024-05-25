use std::convert::TryFrom;

use crossbeam::Sender;
use pnet::packet::ethernet::EthernetPacket;

use crate::{packet_capture::handle_ethernet_packet, structs::PacketInfo};

pub fn pcap_parse(path: &str, tx: Sender<PacketInfo>) {
    use pcap_parser::traits::PcapReaderIterator;
    use pcap_parser::*;
    use std::fs::File;

    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    let mut if_linktypes = Vec::new();
    let mut last_incomplete_index = 0;
    let mut process_block_info = Vec::new();

    #[derive(Default, Debug)]
    struct ProcInfo {
        pid: u32,
        name: Option<String>,
    }

    loop {
        std::thread::sleep(std::time::Duration::from_millis(10));
        match reader.next() {
            Ok((offset, block)) => {
                println!("got new block");
                num_blocks += 1;
                match block {
                    PcapBlockOwned::NG(Block::ProcessInformation(ref proc)) => {
                        // println!("Proc block {proc:?}");

                        let mut info = ProcInfo::default();
                        info.pid = proc.process_id;

                        for option in &proc.options {
                            // println!("code: {} [{}]", option.code.0, option.len);

                            match option.code.0 {
                                2 => {
                                    // process name
                                    let name = std::str::from_utf8(option.value())
                                        .map(|v| v.to_owned())
                                        .ok();
                                    info.name = name;
                                }
                                3 => {
                                    // process path
                                    // let value = std::str::from_utf8(option.value());
                                    // println!("{value:?}");
                                }
                                4 => {
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
                        println!("SectionHeader {_shb:?}");
                        // starting a new section, clear known interfaces
                        if_linktypes = Vec::new();
                        process_block_info = Vec::new();
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        println!("InterfaceDescription {idb:?}");
                        if_linktypes.push(idb.linktype);
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        // println!("enhanced packet {epb:?}");

                        let mut process = None;
                        for option in &epb.options {
                            if option.code.0 == 0x8001 {
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
                        println!("pid: {process:?}");
                        handle_ethernet_packet(&ether, &tx);

                        // let res = pcap_parser::data::get_packetdata(
                        //     epb.data,
                        //     linktype,
                        //     epb.caplen as usize,
                        // );
                    }
                    PcapBlockOwned::NG(Block::SimplePacket(ref spb)) => {
                        println!("simple packet {spb:?}");
                        assert!(if_linktypes.len() > 0);
                        let linktype = if_linktypes[0];
                        let blen = (spb.block_len1 - 16) as usize;
                        #[cfg(feature = "data")]
                        let res = pcap_parser::data::get_packetdata(spb.data, linktype, blen);
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
     #define	PCAPNG_PIB_NAME			2	/* UTF-8 string with name of process */
     #define	PCAPNG_PIB_PATH			3	/* UTF-8 string with path of process */
     #define	PCAPNG_PIB_UUID			4	/* 16 bytes of the process UUID */

     pcap_ng_dump_proc_info
     https://github.com/apple-opensource/libpcap/blob/dc199b42a8206254d1705d5612f7b26414252152/libpcap/pcap-darwin.c#L737
     pcap_ng_dump_proc - responsible for writing the process info block
     pcap_ng_dump_pktap_v2 - dumps pktap

     pcap_proc_info_set_add_uuid

     PCAPNG_EPB_PIB_INDEX
     PCAPNG_EPB_E_PIB_INDEX

     pcap_ng_dump_pktap
*/
