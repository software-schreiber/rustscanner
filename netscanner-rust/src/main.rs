mod scans;
mod flags;

use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::time::{Instant};
use std::{env};
use flags::{ScanFlags};
use scans::{scan_ports_from_ip, scan_ports_from_ip_range, scan_ports_from_subnet_cidr};

const DEFAULT_MAX_THREADS: usize = 512;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() <= 1 {
        println!("There should be at least one argument. Type 'help' to get extended information");
        return
    }

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
        println!("          -t <Number>                     Set the number of threads to use for scanning (default: {})", DEFAULT_MAX_THREADS);
        println!("          -p                              Prohibit the use of pinging (takes more time)");
        std::process::exit(0);
    }

    let timestamp = Instant::now();
    let flags = ScanFlags::new(
        args.contains(&String::from("-a")),
        args.contains(&String::from("-p")),
        if args.contains(&String::from("-t")) {
            args.get(args.iter().position(|x| x == "-t").unwrap() + 1)
                .unwrap()
                .parse::<usize>()
                .unwrap()
        } else {
            DEFAULT_MAX_THREADS
        }
    );

    if first_argument.eq("this") {
        let dummy_socket = UdpSocket::bind("0.0.0.0:0").unwrap();
        let own_ip = dummy_socket.local_addr().unwrap();
        scan_ports_from_ip(
            match own_ip.ip() {
                IpAddr::V4(v4) => v4,
                _ => {
                    panic!("Obtained other address than IPv4");
                },
            },
            flags,
            None,
            None,
            None
        );
    } else if first_argument.eq("device") {
        if args.len() < 3 {
            println!("The argument 'device' requires one more argument. Type 'help' to get extended information");
            std::process::exit(1);
        }
        let ip_addr: Ipv4Addr = args.get(2).unwrap().parse::<Ipv4Addr>().unwrap();
        scan_ports_from_ip(
            ip_addr,
            flags,
            None,
            None,
            None
        );
    } else if first_argument.eq("range") {
        if args.len() < 4 {
            println!("The argument 'device' requires two extra arguments. Type 'help' to get extended information");
            std::process::exit(1);
        }
        let first_ip_addr: Ipv4Addr = args.get(2).unwrap().parse::<Ipv4Addr>().unwrap();
        let last_ip_addr: Ipv4Addr = args.get(3).unwrap().parse::<Ipv4Addr>().unwrap();
        scan_ports_from_ip_range(
            first_ip_addr,
            last_ip_addr,
            flags,
            None
        );
    } else if first_argument.eq("subnet") {
        if args.len() < 4 {
            println!("The argument 'subnet' requires two extra arguments. Type 'help' to get extended information");
            std::process::exit(1);
        }
        let first_ip_addr: Ipv4Addr = args.get(2).unwrap().parse::<Ipv4Addr>().unwrap();
        let range = args.get(3).unwrap().parse::<u8>().unwrap();
        scan_ports_from_subnet_cidr(
            first_ip_addr,
            range,
            flags
        );
    } else {
        println!("Unknown first argument '{}'. Type 'help' or '?' to see available options", first_argument);
        std::process::exit(1);
    }

    println!("\nScanning completed in {:?}", timestamp.elapsed());
}
