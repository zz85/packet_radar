use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct PacketInfo {
    pub len: u16,
    pub src: String,
    pub dest: String,
    pub src_port: u16,
    pub dest_port: u16,
    pub t: String, // type: t for tcp, u for udp
                   // todo timestamp + id
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
