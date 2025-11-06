mod scans;

use std::net::{IpAddr, Ipv4Addr,UdpSocket};
use std::time::{Instant};
use std::{env};
use scans::{MAXIMUM_THREADS, scan_ports_from_ip, scan_ports_from_ip_range, scan_ports_from_subnet_cidr};

const MAXIMUM_THREADS_FOR_SINGLE_IP: usize = 50;

fn main() {
    let timestamp = Instant::now();
    let args: Vec<String> = env::args().collect();

    let scan_all_ports: bool = args.contains(&String::from("-a"));
    let maximum_threads: (usize, bool) = {
        if args.contains(&String::from("-t")) {
            (args.get(args.iter().position(|x| x == "-t").unwrap() + 1)
                .unwrap()
                .parse::<usize>()
                .unwrap(), true)
        } else {
            (MAXIMUM_THREADS, false)
        }
    };

    let first_argument = args.get(1).unwrap();
    if first_argument.eq("help") || first_argument.eq("?") {
        println!("Syntax:   rustscanner <usage> [options]");
        println!();
        println!("Usage:    help                            Shows this text");
        println!("          this                            Scans important ports of the current device");
        println!("          device <IP>                     Scans important ports of the given IP");
        println!("          range <Start_IP> <End_IP>       Scans important ports of all IPs in the range [Start; End]");
        println!("          subnet <IP> <CIDR>              Scans important ports of in subnet");
        println!("Options:  -a                              Scan all ports (time consuming)");
        println!("          -t <NUMBER>                     Set the number of threads to use for scanning (default: {})", MAXIMUM_THREADS);
        std::process::exit(0);
    } else if first_argument.eq("this") {
        let dummy_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let own_ip = dummy_socket.local_addr().unwrap();
        scan_ports_from_ip(
            match own_ip.ip() {
                IpAddr::V4(v4) => v4,
                _ => {
                    panic!("Obtained other address than IPv4");
                },
            },
            scan_all_ports,
            {
                if !maximum_threads.1 {
                    Some(MAXIMUM_THREADS_FOR_SINGLE_IP)
                } else {
                    Some(maximum_threads.0)
                }
            },
            None
        );
    } else if first_argument.eq("device") {
        let ip_addr: Ipv4Addr = args.get(2).unwrap().parse::<Ipv4Addr>().unwrap();
        scan_ports_from_ip(
            ip_addr,
            scan_all_ports,
            {
                if !maximum_threads.1 {
                    Some(MAXIMUM_THREADS_FOR_SINGLE_IP)
                } else {
                    Some(maximum_threads.0)
                }
            },
            None
        );
    } else if first_argument.eq("range") {
        let first_ip_addr: Ipv4Addr = args.get(2).unwrap().parse::<Ipv4Addr>().unwrap();
        let last_ip_addr: Ipv4Addr = args.get(3).unwrap().parse::<Ipv4Addr>().unwrap();
        scan_ports_from_ip_range(
            first_ip_addr,
            last_ip_addr,
            scan_all_ports,
            Some(maximum_threads.0)
        );
    } else if first_argument.eq("subnet") {
        let first_ip_addr: Ipv4Addr = args.get(2).unwrap().parse::<Ipv4Addr>().unwrap();
        let range = args.get(3).unwrap().parse::<u8>().unwrap();
        scan_ports_from_subnet_cidr(
            first_ip_addr,
            range,
            scan_all_ports,
            Some(maximum_threads.0)
        );
    } else {
        eprintln!("Unknown first argument: {}; Type 'help' or '?' to see available options", first_argument);
        std::process::exit(1);
    }
    println!("Scan complete.");
    println!("Total time: {:?}", timestamp.elapsed());
}
