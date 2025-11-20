use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub ip: IpAddr,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub device_type: String,
    pub ports: Vec<u16>,
    pub latency: f32,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct NetworkTopology {
    pub devices: Vec<Device>,
    pub gateway: IpAddr,
    pub subnet: String,
    pub total_devices: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
}

#[derive(Serialize, Clone, Debug, Deserialize)]
pub struct Link {
    pub source: String,
    pub target: String,
    pub value: f32,
}
