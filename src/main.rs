use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;
use std::{env, thread};

fn main() {
    // Accepts optional args: <ip-or-host>
    let args: Vec<String> = env::args().collect();
    let host = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "192.168.0.69".to_string());    

    // Collect join handles so the program waits for all threads to finish.
    let mut handles = Vec::new();
    for port in 0..=u16::MAX {
        // Clone host for the thread so the closure owns its data
        let host_clone = host.clone();

        let handle = thread::spawn(move || {
            let addr_str = format!("{}:{}", host_clone, port);

            let addrs: Vec<_> = match addr_str.to_socket_addrs() {
                Ok(iter) => iter.collect(),
                Err(e) => {
                    eprintln!("Failed to resolve {}: {}", addr_str, e);
                    return;
                }
            };

            if addrs.is_empty() {
                return;
            }

            let timeout = Duration::from_secs(1);

            // Try all resolved addresses; if any succeeds, report OPEN.
            for addr in addrs {
                if TcpStream::connect_timeout(&addr, timeout).is_ok() {
                    println!("OPEN {}", addr);
                }
            }
        });

        handles.push(handle);
    }

    // Wait for all spawned threads to finish.
    for h in handles {
        // Ignore join errors (thread panicked) — handle as needed.
        let _ = h.join();
    }

    println!("Scan complete.");
}
