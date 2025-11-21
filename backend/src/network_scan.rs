use super::models::{Device, NetworkTopology};
use dns_lookup::lookup_addr;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::AsyncResolver;
use pnet::datalink;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use tokio::net::TcpStream as TokioTcpStream;
use tokio::time::{timeout, Duration};

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

async fn check_tcp_port(ip: IpAddr, port: u16, timeout_ms: u64) -> bool {
    let addr = format!("{}:{}", ip, port);
    match timeout(
        Duration::from_millis(timeout_ms),
        TokioTcpStream::connect(addr),
    )
    .await
    {
        Ok(Ok(_)) => true,
        _ => false,
    }
}

pub async fn scan_host(ip: IpAddr) -> Option<Device> {
    let start_time = Instant::now();

    // Enhanced reachability check and port collection
    let interesting_ports = vec![
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3128, 3306, 3389,
        5432, 5900, 8000, 8080, 8443, 8888, // Common ports
        10000, 20000, // Webmin, Virtualmin
        8006,  // Proxmox web interface
    ];
    let mut open_ports: Vec<u16> = Vec::new();
    let mut is_reachable = false;

    for port in interesting_ports.iter() {
        if check_tcp_port(ip, *port, 300).await {
            open_ports.push(*port);
            is_reachable = true;
        }
    }

    if !is_reachable {
        return None;
    }

    let hostname = get_hostname(ip).await;
    let mac = get_mac_address(ip).await;
    let latency = start_time.elapsed().as_secs_f32() * 1000.0 / 254.0; // Approximate latency

    let device_type = determine_device_type(hostname.as_ref(), &open_ports);

    Some(Device {
        ip,
        hostname,
        mac,
        device_type,
        latency,
        open_ports,
    })
}

async fn get_hostname(ip: IpAddr) -> Option<String> {
    if let Ok(host) = lookup_addr(&ip) {
        if !host.is_empty() && host != ip.to_string() {
            eprintln!(
                "DEBUG: Found hostname for {} using dns-lookup: {}",
                ip, host
            );
            return Some(host);
        }
    } else {
        eprintln!("DEBUG: dns-lookup failed for {}.", ip);
    }

    let resolver = match AsyncResolver::from_system_conf(TokioConnectionProvider::default()) {
        Ok(r) => r,
        Err(e) => {
            eprintln!(
                "ERROR: Failed to create DNS resolver from system config: {:?}",
                e
            );
            return None;
        }
    };

    match resolver.reverse_lookup(ip).await {
        Ok(response) => {
            if let Some(name) = response.iter().next() {
                let hostname = name.to_string().trim_end_matches('.').to_string();
                if !hostname.is_empty() && hostname != ip.to_string() {
                    eprintln!(
                        "DEBUG: Found hostname for {} using hickory-resolver: {}",
                        ip, hostname
                    );
                    return Some(hostname);
                }
            }
        }
        Err(e) => {
            eprintln!("DEBUG: hickory-resolver failed for {}: {:?}", ip, e);
        }
    }

    None
}

async fn get_mac_address(ip: IpAddr) -> Option<String> {
    for iface in datalink::interfaces() {
        if let Some(mac) = iface.mac {
            for ip_network in &iface.ips {
                if ip_network.ip() == ip {
                    return Some(mac.to_string());
                }
            }
        }
    }
    eprintln!(
        "DEBUG: No MAC address found for {}. (Only local interfaces are checked).",
        ip
    );
    None
}

fn determine_device_type(hostname: Option<&String>, open_ports: &[u16]) -> String {
    if let Some(h) = hostname {
        let lower_h = h.to_lowercase();
        if lower_h.contains("router") || lower_h.contains("gateway") {
            return "Router/Gateway".to_string();
        }
        if lower_h.contains("printer") {
            return "Printer".to_string();
        }
        if lower_h.contains("nas") {
            return "NAS".to_string();
        }
        if lower_h.contains("desktop") || lower_h.contains("pc") || lower_h.contains("computer") {
            return "Desktop".to_string();
        }
        if lower_h.contains("mobile") || lower_h.contains("phone") || lower_h.contains("tablet") {
            return "Mobile".to_string();
        }
        if lower_h.contains("pve") || open_ports.contains(&8006) {
            return "Proxmox Server".to_string();
        }
        if lower_h.contains("server") {
            return "Server".to_string();
        }
    }

    if open_ports.contains(&22) {
        return "SSH Server".to_string();
    }
    if open_ports.contains(&80) || open_ports.contains(&443) {
        return "Web Server".to_string();
    }
    if open_ports.contains(&3306) {
        return "MySQL Server".to_string();
    }
    if open_ports.contains(&5432) {
        return "PostgreSQL Server".to_string();
    }
    if open_ports.contains(&3389) {
        return "RDP Host".to_string();
    }
    if open_ports.contains(&5900) {
        return "VNC Host".to_string();
    }
    if open_ports.contains(&21) {
        return "FTP Server".to_string();
    }
    if open_ports.contains(&23) {
        return "Telnet Server".to_string();
    }
    if open_ports.contains(&25) {
        return "SMTP Server".to_string();
    }
    if open_ports.contains(&110) {
        return "POP3 Server".to_string();
    }
    if open_ports.contains(&143) {
        return "IMAP Server".to_string();
    }
    if open_ports.contains(&139) || open_ports.contains(&445) {
        return "SMB/Samba Server".to_string();
    }

    "Unknown".to_string()
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
