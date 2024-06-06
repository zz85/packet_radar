use clap::Parser;

#[derive(Parser, Debug, Clone, Default)]
#[command(version, about, long_about = None)]
pub struct Args {
    // #[arg(short, long, default_value_t = true)]
    // top: bool,
    #[arg(short, long)]
    pub monitoring: bool,

    /// websockets support
    #[arg(short, long, default_value_t = true)]
    pub ws: bool,

    /// websocket bind addr
    #[arg(short, long, default_value = "127.0.0.1:3012")]
    pub server: String,

    /// Network interface
    #[arg(short, long)]
    pub interface: Option<String>,

    #[arg(short, long, default_value_t = false)]
    pub tls_fingerprint: bool,

    #[arg(short, long)]
    pub pcap_file: Option<String>,
}
