# Packet Radar

Packet Radar is an experimental realtime network traffic visualization.

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

Server uses rust, UI is done with Canvas + JS.

### Server

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

### IDEAs / TODO
- [x] DNS resolution
- [x] Find local addresses
- [x] Ping / ICMP Traceroute probes
- [ ] TCP/UDP trace probes
- [x] Traffic categorization (UDP, TCP,..
- [ ] TLS, QUIC)
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
