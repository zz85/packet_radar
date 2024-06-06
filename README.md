# Packet Radar

Packet Radar is an experimental realtime network traffic analyzer and visualizer.

It captures packets like pcap and displays the information in various ways like wireshark.

- packet fight viz - visualizes and animates packets transferring between hosts.
- packet stats - a dashboard showing real-time network telemetry like data rates.
- packet top - shows top connections
- packet tail - a simple packet log viewer

This started as a weekend project project for
- playing around with rust
- exploring and understanding some network protocol details
- playing around with visualizations, animations and simulations

If you like this, you may also be interested in [Space Rader](https://github.com/zz85/space-radar), a disk space visualization app.

Core code is written in rust, Visualization UI is done with Canvas + JS.

### Utilities

`ja4dump` - like tcpdump but for JA4 TLS client fingerprinting
`ja4top` - shows ja4 and associated processes

### Building

```
### If you need to install rust
curl https://sh.rustup.rs -sSf | sh

### Compile and run
cargo run

### On Linux Kernel >= 2.2
cargo build
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/packet_radar
cargo run

(s/debug/release if --release)

### Or if you require sudo
cargo build
sudo target/debug/packet_radar -m

(s/debug/release if `--release`)
```

### Technical

There are 3 ways packets are processed -
1. using pcap lib
2. using pnet datalink
3. using pcapng parsing

The main module parses the network packets, depending on what protocol has been implemented.
Some state is kept in statically, while tcp+udp packets as well as JA4 events are emitted via
a crossbeam mpsc channel.

The evented model allows writing isolated experiments by rebuilding state while collecting events.
One example is ja4dump, and others through the web visualization that's basically a broadcast of
the mpsc channels proxied over websockets to the browser.

Another way to write modules is to access the shared state. One example is ja4top.

Or a module who take a combination of both. One example is processes rs where it build it own "top"
state, but it also has the ability to access the shared connection states to enrich it with process
infomation.

### Visualization

```
open `html/packet_viz.html` in your browser
```

### Contributors

- Joshua Koo
- Yang Bin Kwok

### Related projects
- https://github.com/kpcyrd/sniffglue
- https://github.com/imsnif/bandwhich


### ChangeLog
Jun 5, 2024 - basic QUIC client hello parsing (available in packet_radar, ja4dump, ja4top)

May 24, 2024 - Ability to read from pcap file or stdin (eg. sudo tcpdump -w - | sudo packet_radar -p -  ).
On macs, tcpdump using pktap will provide process id information during packet capture.
This method requires sudo, but for unprivileged users, the lsof method will be the fallback.

### IDEAs / TODO
- [x] DNS resolution
- [x] Find local addresses
- [x] Ping / ICMP Traceroute probes
- [ ] TCP/UDP trace probes
- [x] Traffic categorization (UDP, TCP,..
- [x] TLS, QUIC)
- [x] DNS capture
- [ ] RTT / light distance Analysis
- [ ] Packet replay
- [ ] Terminal interface
- [ ] Visual traceroute
- [-] Geoip / ASN breakdown
- [ ] Whois / What's my ip whatsmyip
- [ ] SSL Key log decoding
- [x] TLS Parsing and Fingerprinting
   - [x] JA4 Fingerprinting stats by processes
   - [ ] TLS Stats
- [-] Quic Packet Parsing
- [ ] Sankey diagrams
- [x] Netstat / Socket listings
- [x] Break connections by processes - Top process bandwidth
- [x] Top connection/processes by bandwidth
- [ ] Viz: breakdown by processes
- [ ] Metadata mapping
- [ ] Plugable architecture
