use super::models::{Device, NetworkTopology};
use dns_lookup::lookup_addr;
use hickory_resolver::name_server::TokioConnectionProvider;
use hickory_resolver::AsyncResolver;
use pnet::datalink::{self, MacAddr};
use pnet::packet::arp::{ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::{MutablePacket, Packet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use tokio::net::{TcpStream as TokioTcpStream, UdpSocket as TokioUdpSocket};
use tokio::sync::oneshot;
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

async fn check_udp_port(ip: IpAddr, port: u16, timeout_ms: u64) -> bool {
    let bind_addr = if ip.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    match TokioUdpSocket::bind(bind_addr).await {
        Ok(socket) => {
            let _ = socket.send_to(&[], format!("{}:{}", ip, port)).await;
            match timeout(
                Duration::from_millis(timeout_ms),
                socket.recv_from(&mut [0u8; 0]),
            )
            .await
            {
                Ok(Ok(_)) => true,
                _ => false,
            }
        }
        Err(_) => false,
    }
}

pub async fn scan_host(ip: IpAddr) -> Option<Device> {
    let start_time = Instant::now();

    let tcp_ports_to_scan = vec![
        21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 995, 1723, 3128, 3306, 3389,
        5432, 5900, 8000, 8080, 8443, 8888, 10000, 20000, 8006,
    ];
    let udp_ports_to_scan = vec![53, 67, 68, 69, 123, 161, 162, 500, 1701, 4500, 5353, 5678];

    let mut open_ports: Vec<u16> = Vec::new();
    let mut is_reachable = false;

    for port in tcp_ports_to_scan.iter() {
        if check_tcp_port(ip, *port, 300).await {
            open_ports.push(*port);
            is_reachable = true;
        }
    }

    for port in udp_ports_to_scan.iter() {
        if check_udp_port(ip, *port, 300).await {
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
    if !ip.is_ipv4() {
        eprintln!(
            "DEBUG: ARP scan not supported for IPv6 addresses. No MAC address found for {}.",
            ip
        );
        return None;
    }

    let local_ip_info = get_local_network_info().await?;
    let local_ipv4 = match local_ip_info.0 {
        IpAddr::V4(ipv4) => ipv4,
        _ => return None,
    };

    let local_interface = datalink::interfaces()
        .into_iter()
        .find(|iface| iface.ips.iter().any(|ip_n| ip_n.ip() == local_ip_info.0))?;

    let sender_mac = local_interface.mac?;
    let target_ipv4 = match ip {
        IpAddr::V4(ipv4) => ipv4,
        _ => return None,
    };

    let (response_tx, response_rx) = oneshot::channel();

    tokio::spawn(arp_scan(
        local_interface.name.clone(), // Clone the String
        target_ipv4,
        local_ipv4,
        sender_mac,
        response_tx,
    ));

    match timeout(Duration::from_millis(1000), response_rx).await {
        Ok(Ok((_ip, mac))) => {
            eprintln!("DEBUG: Found MAC address for {} using ARP: {}", ip, mac);
            Some(mac.to_string())
        }
        _ => {
            eprintln!("DEBUG: No MAC address found for {} using ARP.", ip);
            None
        }
    }
}

async fn arp_scan(
    interface_name: String, // Changed to owned String
    target_ip: Ipv4Addr,
    sender_ip: Ipv4Addr,
    sender_mac: MacAddr,
    response_tx: oneshot::Sender<(Ipv4Addr, MacAddr)>,
) {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface| iface.name == interface_name)
        .next()
        .expect("Failed to get interface");

    let (mut tx, _rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    let mut ethernet_buffer = [0u8; 42];
    let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

    let mut arp_buffer = [0u8; 28];
    let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

    // Build ARP request
    arp_packet.set_hardware_type(pnet::packet::arp::ArpHardwareType::new(1));
    arp_packet.set_protocol_type(pnet::packet::ethernet::EtherType::new(0x0800));
    arp_packet.set_hw_addr_len(6);
    arp_packet.set_proto_addr_len(4);
    arp_packet.set_operation(ArpOperations::Request);
    arp_packet.set_sender_hw_addr(sender_mac);
    arp_packet.set_sender_proto_addr(sender_ip);
    arp_packet.set_target_hw_addr(MacAddr::broadcast());
    arp_packet.set_target_proto_addr(target_ip);

    // Build Ethernet header
    ethernet_packet.set_destination(MacAddr::broadcast());
    ethernet_packet.set_source(sender_mac);
    ethernet_packet.set_ethertype(pnet::packet::ethernet::EtherType::new(1));
    ethernet_packet.set_payload(arp_packet.packet_mut());

    tx.send_to(ethernet_packet.packet(), None);

    // Listen for ARP reply
    let (mut _tx, mut rx) = match datalink::channel(&interface, Default::default()) {
        Ok(datalink::Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("Unknown channel type"),
        Err(e) => panic!("Error creating datalink channel: {}", e),
    };

    let response_timeout = Duration::from_millis(500); // Shorter timeout for ARP responses
    let start_time = Instant::now();

    while start_time.elapsed() < response_timeout {
        match rx.next() {
            Ok(packet) => {
                if let Some(ethernet_packet) = EthernetPacket::new(packet) {
                    if ethernet_packet.get_ethertype() == pnet::packet::ethernet::EtherType::new(1)
                    {
                        if let Some(arp) = ArpPacket::new(ethernet_packet.payload()) {
                            if arp.get_operation() == ArpOperations::Reply
                                && arp.get_sender_proto_addr() == target_ip
                            {
                                let _ = response_tx
                                    .send((arp.get_sender_proto_addr(), arp.get_sender_hw_addr()));
                                return;
                            }
                        }
                    }
                }
            }
            Err(e) => eprintln!("Error receiving packet: {:?}", e),
        }
    }
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

pub async fn scan_network(target_subnet: Option<String>) -> Option<NetworkTopology> {
    let (_local_ip, gateway_ip, default_subnet) = get_local_network_info().await?;
    let subnet_to_scan = target_subnet.unwrap_or(default_subnet);

    let network: ipnetwork::IpNetwork = subnet_to_scan.parse().ok()?;
    let mut hosts: Vec<IpAddr> = Vec::new();

    match network {
        ipnetwork::IpNetwork::V4(ipv4_network) => {
            let base_ip_octets = ipv4_network.network().octets();
            for i in 1..=254 {
                // Iterate through the last octet for a /24 subnet (common case)
                let ip_str = format!(
                    "{}.{}.{}.{}",
                    base_ip_octets[0], base_ip_octets[1], base_ip_octets[2], i
                );
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    hosts.push(ip);
                }
            }
        }
        ipnetwork::IpNetwork::V6(_) => {
            eprintln!(
                "DEBUG: IPv6 network scanning is not yet fully implemented for custom ranges."
            );
            // For now, if IPv6, we'll return None or handle a specific default.
            // A more robust implementation would involve iterating IPv6 ranges.
            return None;
        }
    }

    let mut handles = Vec::new();
    for ip in hosts {
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
        subnet: subnet_to_scan,
        total_devices,
        links: None,
    })
}
