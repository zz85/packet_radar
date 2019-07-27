# Packet Radar

Packet Radar is an experimental weekend project for visualizing network traffic.

It is a project for
- playing around with rust
- playing around with understanding packets
- playing around with visualizations, animations and simulations

Server uses nightly rust, UI is done with Canvas + JS.

### Server

```
### If you need to install rust
curl https://sh.rustup.rs -sSf | sh
rustup install nightly
rustup default nightly

### Compile and run
cargo run

### Or if you require sudo
cargo build
sudo target/debug/packet_radar
```

### Visualization

```
open `html/packet_viz.html` in your browser
```

### Contributors

- Joshua Koo
- Yangbin Kwok

