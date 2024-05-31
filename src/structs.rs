use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct PacketInfo {
    pub len: u16,
    pub src: String,
    pub dest: String,
    pub src_port: u16,
    pub dest_port: u16,
    pub t: PacketType, // type: t for tcp, u for udp
    // todo timestamp + id
    pub pid: Option<u32>,
    pub process: Option<String>,
    pub ja4: Option<String>,
    pub sni: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub enum PacketType {
    #[default]
    #[serde(rename = "t")]
    Tcp,
    #[serde(rename = "u")]
    Udp,
    #[serde(rename = "j")]
    Ja4,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct ClientRequest {
    pub req: String,
    #[serde(default = "default_type")]
    pub r#type: String,
    pub value: String,
}

fn default_type() -> String {
    "".to_string()
}

#[derive(Default, Debug)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: Option<String>,
}
