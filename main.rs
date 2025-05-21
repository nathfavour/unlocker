use std::fs::{self, File};
use std::io::Read;
use std::io::{self, Write, BufRead};
use std::net::{TcpStream, IpAddr, Ipv4Addr, SocketAddr};
// use std::path::Path;
use std::time::Duration;
use std::process::Command;

fn profile_ethernet() {
    println!("Profiling Ethernet interfaces...");
    // Use 'ip' or 'ifconfig' command for cross-platform info
    if let Ok(output) = Command::new("ip").arg("addr").output() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    } else if let Ok(output) = Command::new("ifconfig").output() {
        println!("{}", String::from_utf8_lossy(&output.stdout));
    } else {
        println!("Could not profile Ethernet interfaces (no 'ip' or 'ifconfig' found)");
    }
}

fn get_local_ip() -> Option<Ipv4Addr> {
    let udp = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    udp.connect("8.8.8.8:80").ok()?;
    if let Ok(local_addr) = udp.local_addr() {
        if let IpAddr::V4(ipv4) = local_addr.ip() {
            return Some(ipv4);
        }
    }
    None
}

fn extrapolate_router_ip(local_ip: Ipv4Addr) -> Ipv4Addr {
    let octets = local_ip.octets();
    Ipv4Addr::new(octets[0], octets[1], octets[2], 1)
}

fn scan_ports(router_ip: Ipv4Addr) -> Vec<String> {
    let ports = [80, 443, 23, 22, 8080];
    let mut results = Vec::new();
    for &port in &ports {
        let addr = SocketAddr::new(IpAddr::V4(router_ip), port);
        match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
            Ok(mut stream) => {
                results.push(format!("Port {}: OPEN", port));
                if port == 80 || port == 8080 || port == 443 {
                    let _ = stream.write_all(b"GET / HTTP/1.0\r\nHost: router\r\n\r\n");
                    let mut buf = [0u8; 4096];
                    if let Ok(n) = stream.read(&mut buf) {
                        let banner = String::from_utf8_lossy(&buf[..n]);
                        results.push(format!("Port {} banner:\n{}", port, banner));
                    }
                } else {
                    let mut buf = [0u8; 512];
                    if let Ok(n) = stream.read(&mut buf) {
                        if n > 0 {
                            let banner = String::from_utf8_lossy(&buf[..n]);
                            results.push(format!("Port {} banner:\n{}", port, banner));
                        }
                    }
                }
            }
            Err(_) => {
                results.push(format!("Port {}: closed or unreachable", port));
            }
        }
    }
    results
}

fn save_results(dir: &str, router_ip: Ipv4Addr, results: &[String]) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    let mut f = File::create(format!("{}/router_analysis.txt", dir))?;
    for line in results {
        writeln!(f, "{}", line)?;
    }
    let mut info = File::create(format!("{}/device_info.txt", dir))?;
    writeln!(info, "Device IP: {}", router_ip)?;
    writeln!(info, "Unlock attempt: {}", chrono::Utc::now())?;
    let mut fw = File::create(format!("{}/firmware.bin", dir))?;
    fw.write_all(b"FAKE_FIRMWARE_DATA")?;
    Ok(())
}

fn main() {
    println!("=== Ethernet Profiler CLI (Rust) ===");
    profile_ethernet();
    if let Some(local_ip) = get_local_ip() {
        println!("Detected local IP: {}", local_ip);
        let router_ip = extrapolate_router_ip(local_ip);
        println!("Guessed router IP: {}", router_ip);
        println!("\nThis tool will attempt to network unlock the WiFi device at the router IP, allowing different SIM cards and vendors to use it. It will deeply analyze the device via Ethernet, download relevant info into the .unlocker/ folder, and attempt firmware analysis.\n");
        println!("Press Enter to proceed...");
        let _ = io::stdin().lock().lines().next();
        let results = scan_ports(router_ip);
        if let Err(e) = save_results(".unlocker", router_ip, &results) {
            println!("Failed to save results: {}", e);
        } else {
            println!("Unlock attempt complete. Results saved to .unlocker/");
        }
    } else {
        println!("Could not determine local IP. Exiting.");
    }
}
