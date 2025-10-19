use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::{env, thread};

fn main() {
    let timestamp = Instant::now();
    let args: Vec<String> = env::args().collect();
    let host = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "192.168.0.69".to_string());

    let mut handles = Vec::new();
    for port in 0..=u16::MAX {
        let host_clone = host.clone();

        handles.push(thread::spawn(move || {
            let addr_str = format!("{}:{}", host_clone, port);

            let addrs: Vec<_> = match addr_str.to_socket_addrs() {
                Ok(iter) => iter.collect(),
                Err(e) => {
                    eprintln!("Failed to resolve {}: {}", addr_str, e);
                    return;
                }
            };
            
            let timeout = Duration::from_secs(3);

            for addr in addrs {
                if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                    println!("OPEN {}", addr);
                }
            }
        }));
    }

    for h in handles {
        let _ = h.join();
    }

    println!("Scan complete.");
    println!("Total time: {:?}", timestamp.elapsed());
}
