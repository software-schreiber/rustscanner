use std::env;
use std::net::{TcpStream, ToSocketAddrs};
use std::process::exit;
use std::time::Duration;

fn main() {
    // Default target from your request. Accepts optional args: <ip> <port>
    let args: Vec<String> = env::args().collect();
    let host = args.get(1).map(|s| s.as_str()).unwrap_or("192.168.0.114");

    for port in 0..=u16::MAX {
        let addr_str = format!("{}:{}", host, port);

        let addrs: Vec<_> = match addr_str.to_socket_addrs() {
            Ok(iter) => iter.collect(),
            Err(e) => {
                eprintln!("Failed to resolve {}: {}", addr_str, e);
                continue;
            }
        };

        if addrs.is_empty() {
            //eprintln!("No socket addresses found for {}", addr_str);
            //std::process::exit(2);
            continue;
        }

        let timeout = Duration::from_secs(1);

        // Try all resolved addresses; if any succeeds, report OPEN.
        for addr in addrs {
            if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                println!("OPEN {}", addr);
            }
        }
    }
    println!("All addresses tried; port appears closed or filtered.");
    exit(2);
}

