mod scans;

use std::net::{IpAddr, Ipv4Addr};
use std::time::{Instant};
use std::{env};
use scans::scan_ports_from_ip;

use crate::scans::{scan_ports_from_ip_range, scan_ports_from_subnet_cidr};

fn main() {
    let timestamp = Instant::now();
    let args: Vec<String> = env::args().collect();
    let host = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "127.0.0.1".to_string());

    let x = Ipv4Addr::new(192, 168, 0, 100);
    let y = Ipv4Addr::new(192, 168, 0, 71);

    scan_ports_from_subnet_cidr(x, 24);

    println!("Scan complete.");
    println!("Total time: {:?}", timestamp.elapsed());
}
