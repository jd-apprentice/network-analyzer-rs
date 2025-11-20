use super::models::{Device, NetworkTopology};
use pnet::datalink;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;

pub async fn get_local_network_info() -> Option<(IpAddr, IpAddr, String)> {
    for iface in datalink::interfaces() {
        if !iface.is_loopback() && iface.is_up() && !iface.ips.is_empty() {
            for ip_network in &iface.ips {
                if let IpAddr::V4(ipv4) = ip_network.ip() {
                    let ip_str = ipv4.to_string();
                    let parts: Vec<&str> = ip_str.split('.').collect();
                    if parts.len() == 4 {
                        let gateway_ip = Ipv4Addr::new(
                            parts[0].parse().unwrap_or(0),
                            parts[1].parse().unwrap_or(0),
                            parts[2].parse().unwrap_or(0),
                            1,
                        );
                        let subnet = format!("{}.{}.{}.0/24", parts[0], parts[1], parts[2]);
                        return Some((IpAddr::V4(ipv4), IpAddr::V4(gateway_ip), subnet));
                    }
                }
            }
        }
    }
    None
}

pub async fn scan_host(ip: IpAddr) -> Option<Device> {
    let hostname = get_hostname(ip).await;
    let mac = get_mac_address(ip).await;
    let (ports, latency) = scan_common_ports(ip).await;

    if ports.is_empty() && hostname.is_none() && mac.is_none() {
        return None;
    }

    let device_type = determine_device_type(&ports, hostname.as_ref());

    Some(Device {
        ip,
        hostname,
        mac,
        device_type,
        ports,
        latency,
    })
}

async fn get_hostname(ip: IpAddr) -> Option<String> {
    let output = Command::new("dig")
        .arg("-x")
        .arg(ip.to_string())
        .arg("+short")
        .output()
        .await;

    if let Ok(output) = output {
        if output.status.success() {
            let result = String::from_utf8_lossy(&output.stdout);
            let hostname = result.trim().trim_end_matches('.');
            if !hostname.is_empty() {
                return Some(hostname.to_string());
            }
        }
    }

    let output = Command::new("nmblookup")
        .arg("-A")
        .arg(ip.to_string())
        .output()
        .await;

    if let Ok(output) = output {
        if output.status.success() {
            let result = String::from_utf8_lossy(&output.stdout);
            for line in result.lines() {
                if line.contains("<20> (active)") {
                    if let Some(start) = line.find(" ") {
                        if let Some(end) = line[start..].find(" ") {
                            let hostname = line[start..start + end].trim();
                            if !hostname.is_empty() && hostname != ip.to_string() {
                                return Some(hostname.to_string());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

async fn get_mac_address(ip: IpAddr) -> Option<String> {
    let output = Command::new("arp")
        .arg("-n")
        .arg(ip.to_string())
        .output()
        .await;

    if let Ok(output) = output {
        if output.status.success() {
            let result = String::from_utf8_lossy(&output.stdout);
            for line in result.lines() {
                if line.contains(ip.to_string().as_str()) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() >= 3 && parts[2] != "(incomplete)" {
                        return Some(parts[2].to_string());
                    }
                }
            }
        }
    }
    None
}

async fn scan_common_ports(ip: IpAddr) -> (Vec<u16>, f32) {
    let common_ports = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389, 8080];
    let mut open_ports = Vec::new();
    let start_time = tokio::time::Instant::now();

    for port in common_ports {
        let addr = format!("{}:{}", ip, port);
        if timeout(Duration::from_millis(200), TcpStream::connect(&addr))
            .await
            .is_ok()
        {
            open_ports.push(port);
        }
    }
    let latency = start_time.elapsed().as_secs_f32() * 1000.0 / common_ports.len() as f32;
    (open_ports, latency)
}

fn determine_device_type(ports: &[u16], hostname: Option<&String>) -> String {
    let mut device_types = Vec::new();

    if ports.contains(&80) || ports.contains(&443) || ports.contains(&8080) {
        device_types.push("Web Server");
    }
    if ports.contains(&22) {
        device_types.push("SSH Server");
    }
    if ports.contains(&3389) {
        device_types.push("Remote Desktop");
    }
    if ports.contains(&53) {
        device_types.push("DNS Server");
    }
    if ports.contains(&21) {
        device_types.push("FTP Server");
    }
    if ports.contains(&23) {
        device_types.push("Telnet Server");
    }

    if let Some(h) = hostname {
        let lower_h = h.to_lowercase();
        if lower_h.contains("router") || lower_h.contains("gateway") {
            device_types.push("Router/Gateway");
        }
        if lower_h.contains("printer") {
            device_types.push("Printer");
        }
        if lower_h.contains("nas") {
            device_types.push("NAS");
        }
    }

    if device_types.is_empty() {
        "Unknown".to_string()
    } else {
        device_types.join(", ")
    }
}

pub async fn scan_network() -> Option<NetworkTopology> {
    let (local_ip, gateway_ip, subnet) = get_local_network_info().await?;
    let base_ip = match local_ip {
        IpAddr::V4(ipv4) => {
            let parts: Vec<u8> = ipv4.octets().to_vec();
            format!("{}.{}.{}", parts[0], parts[1], parts[2])
        }
        _ => return None,
    };

    let mut handles = Vec::new();
    for i in 1..=254 {
        let ip: IpAddr = format!("{}.{}", base_ip, i).parse().unwrap();
        let handle = tokio::spawn(async move { scan_host(ip).await });
        handles.push(handle);
    }

    let mut devices = Vec::new();
    for handle in handles {
        if let Some(device) = handle.await.ok().flatten() {
            devices.push(device);
        }
    }

    let total_devices = devices.len();

    Some(NetworkTopology {
        devices,
        gateway: gateway_ip,
        subnet,
        total_devices,
        links: None,
    })
}
