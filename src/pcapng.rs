fn parse(path: &str) {
    use pcap_parser::traits::PcapReaderIterator;
    use pcap_parser::*;
    use std::fs::File;

    let file = File::open(path).unwrap();
    let mut num_blocks = 0;
    let mut reader = PcapNGReader::new(65536, file).expect("PcapNGReader");
    let mut if_linktypes = Vec::new();
    let mut last_incomplete_index = 0;
    loop {
        match reader.next() {
            Ok((offset, block)) => {
                println!("got new block");
                num_blocks += 1;
                match block {
                    PcapBlockOwned::NG(Block::ProcessInformation(ref proc)) => {
                        println!("Proc block {proc:?}");
                    }
                    PcapBlockOwned::NG(Block::SectionHeader(ref _shb)) => {
                        // starting a new section, clear known interfaces
                        if_linktypes = Vec::new();
                    }
                    PcapBlockOwned::NG(Block::InterfaceDescription(ref idb)) => {
                        if_linktypes.push(idb.linktype);
                    }
                    PcapBlockOwned::NG(Block::EnhancedPacket(ref epb)) => {
                        println!("enhanced packet");
                        assert!((epb.if_id as usize) < if_linktypes.len());
                        let linktype = if_linktypes[epb.if_id as usize];

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