# Packet Radar

Packet Radar is a realtime network traffic visualization experiment.

It uses pcap to capture packets and displays the information in various ways like wireshark.

- packet fight viz - visualizes and animates packets transferring between hosts.
- packet stats - a dashboard showing real-time network telemetry like data rates.
- packet top - shows top connections
- packet tail - a simple packet log viwer

This started as a weekend project project for
- playing around with rust
- playing around with understanding packets
- playing around with visualizations, animations and simulations

If you like this, you may also be interested in [Space Rader](https://github.com/zz85/space-radar), a disk space visualization app.

Server uses nightly rust, UI is done with Canvas + JS.

### Server

```
### If you need to install rust
curl https://sh.rustup.rs -sSf | sh
rustup install nightly
rustup default nightly

### Compile and run
cargo run

### On Linux Kernel >= 2.2
cargo build
sudo setcap cap_net_raw,cap_net_admin=eip target/debug/packet_radar
cargo run

(s/debug/release if --release)

### Or if you require sudo
cargo build
sudo target/debug/packet_radar

(s/debug/release if --release)
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
- [ ] Whois
- [x] Ping / ICMP Traceroute probes
- [ ] TCP/UDP trace probes
- [x] Traffic categorization (UDP, TCP,..
- [ ] TLS)
- [x] DNS capture
- [ ] RTT Analysis
- [ ] Packet replay
- [ ] Terminal interface
- [ ] Visual traceroute
- [x] Geoip
- [ ] TLS Parsing
- [ ] Quic Packet Parsing
- [ ] Sankey diagrams
- [x] Netstat / Socket listings
- [x] Break connections by processes - Top process bandwidth
- [ ] What's my ip whatsmyip
- [ ] ASN breakdown
