use std::{net::{Ipv4Addr, TcpStream, ToSocketAddrs}, time::Duration};
use std::net::IpAddr;
use std::sync::{mpsc, Arc, Mutex, MutexGuard};
use ping::ping;
use threadpool::ThreadPool;

pub const MAXIMUM_THREADS: usize = 512;

fn print_ports(ip_addr: Ipv4Addr, open_ports: Vec<u16>) {
    println!("\nOpen ports on {}:", ip_addr);
    for port in open_ports {
        let found_protocol_details = COMMON_PORTS.iter().find(|&&x| x.0 == port);
        if let Some(protocol_details) = found_protocol_details {
            println!("\t{}\t{}", protocol_details.0, protocol_details.1);
        } else {
            println!("\t{}", port);
        }
    }
}

pub fn scan_ports_from_ip(ip_addr: Ipv4Addr, scan_all_ports: bool, maximum_threads: Option<usize>, thread_pool: Option<Arc<ThreadPool>>, mutex_print: Option<&Arc<Mutex<bool>>>) {
    let is_arc_thread_pool = thread_pool.is_some();
    let pool = {
        if is_arc_thread_pool {
            thread_pool.unwrap()
        } else {
            Arc::new(ThreadPool::new(maximum_threads.unwrap_or_else(|| MAXIMUM_THREADS)))
        }
    };
    let (tx, rx) = mpsc::channel();

    for port in 0..=u16::MAX {
        if !scan_all_ports && !COMMON_PORTS.iter().find(|&&x| x.0 == port).is_some() {
            continue;
        }

        let host_clone = ip_addr.clone();
        let tx_clone = tx.clone();

		pool.execute(move || {
            let addr_str = format!("{}:{}", host_clone, port);
            match addr_str.to_socket_addrs() {
                Ok(addrs) => {
                    for addr in addrs {
                        match TcpStream::connect_timeout(&addr, Duration::from_secs(3)) {
                            Ok(_) => {
                                match tx_clone.send(port) {
                                    Ok(()) => {}
                                    Err(_error) => {}
                                }
                                break;
                            }
                            Err(_error) => {}
                        }
                    }
                }
                Err(_error) => {}
            }
        });

    }

    drop(tx);
    if !is_arc_thread_pool {
        pool.join();
    }

    let mut open_ports: Vec<u16> = rx.iter().collect();
    open_ports.sort_unstable();
    if open_ports.len() == 0 {
        //println!("No open ports found on: {}", ip_addr);
    } else {
        if mutex_print.is_some() {
            let mutex_print_handle: MutexGuard<bool> = mutex_print.unwrap().lock().unwrap();
            print_ports(ip_addr, open_ports);
            drop(mutex_print_handle);
        } else {
            print_ports(ip_addr, open_ports);
        }
    }
}

pub fn scan_ports_from_ip_range(start_ip: Ipv4Addr, end_ip: Ipv4Addr, scan_all_ports: bool, maximum_threads: Option<usize>, mutex_print: Option<&Arc<Mutex<bool>>>) {
	let start = u32::from(start_ip);
	let end = u32::from(end_ip);
    let pool = Arc::new(ThreadPool::new(maximum_threads.unwrap_or(MAXIMUM_THREADS)));
    let mutex_print = {
        if mutex_print.is_some() {
            mutex_print.unwrap().clone()
        } else {
            Arc::new(Mutex::new(false))
        }
    };

    for ip_num in start..=end {
        let pool_clone = Arc::clone(&pool);
        let mutex_print_clone = mutex_print.clone();
        pool.execute(move || {
            match ping(IpAddr::V4(Ipv4Addr::from(ip_num)), Some(Duration::new(1, 0)), None, None, None, None) {
                Ok(_) => {scan_ports_from_ip(Ipv4Addr::from(ip_num), scan_all_ports, None, Some(pool_clone), Some(&mutex_print_clone));}
                Err(error) => {
                    return;
                }
            }

		});
	}

    pool.join();
}

pub fn scan_ports_from_subnet_cidr(subnet: Ipv4Addr, cidr: u8, scan_all_ports: bool, maximum_threads: Option<usize>) {
	let host_bits = 32 - cidr;
	let num_ips = 1 << host_bits;
    let mutex_print = Arc::new(Mutex::new(false));

	scan_ports_from_ip_range(subnet, Ipv4Addr::from(u32::from(subnet) + num_ips - 1), scan_all_ports, maximum_threads, Some(&mutex_print));
}


const COMMON_PORTS: &[(u16, &str)] = &[
    (20, "FTP-data"),
    (21, "FTP"),
    (22, "SSH"),
    (23, "Telnet"),
    (25, "SMTP"),
    (53, "DNS"),
    (67, "DHCP (server)"),
    (68, "DHCP (client)"),
    (69, "TFTP"),
    (80, "HTTP"),
    (88, "Kerberos"),
    (110, "POP3"),
    (111, "rpcbind / portmapper"),
    (123, "NTP"),
    (135, "MS RPC / DCOM"),
    (137, "NetBIOS Name"),
    (138, "NetBIOS Datagram"),
    (139, "NetBIOS Session / SMB (older)"),
    (143, "IMAP"),
    (161, "SNMP"),
    (162, "SNMP trap"),
    (179, "BGP"),
    (389, "LDAP"),
    (443, "HTTPS"),
    (445, "SMB / Microsoft-DS"),
    (465, "SMTPS (deprecated)"),
    (512, "rexec"),
    (513, "rlogin"),
    (514, "syslog / rsh"),
    (515, "LPD / printer"),
    (548, "AFP (Apple Filing Protocol)"),
    (631, "IPP (printing)"),
    (636, "LDAPS"),
    (993, "IMAPS"),
    (995, "POP3S"),
    (1080, "SOCKS (proxy)"),
    (1194, "OpenVPN"),
    (1433, "MSSQL"),
    (1434, "MSSQL (UDP)"),
    (1521, "Oracle DB (listener)"),
    (1723, "PPTP"),
    (2049, "NFS"),
    (2082, "cPanel (HTTP)"),
    (2083, "cPanel (HTTPS)"),
    (2375, "Docker API (unsecured)"),
    (2376, "Docker API (TLS)"),
    (27017, "MongoDB"),
    (3000, "Dev servers / web apps"),
    (3306, "MySQL / MariaDB"),
    (3389, "RDP (Windows Remote Desktop)"),
    (37017, "Example DB abuse port (seen in the wild)"),
    (5000, "Dev / UPnP / admin UIs"),
    (5060, "SIP (VoIP)"),
    (5061, "SIP TLS"),
    (5432, "PostgreSQL"),
    (5560, "App-specific (often seen in networks)"),
    (5900, "VNC"),
    (6379, "Redis"),
    (8000, "Alternate HTTP / admin"),
	(8006, "Proxmox VE web GUI"),
    (8008, "Alternate HTTP"),
    (8080, "Alternate HTTP / proxy"),
    (8443, "HTTPS-alt / admin"),
    (9000, "Dev/admin (e.g. php-fpm, dev UIs)"),
    (9200, "Elasticsearch HTTP"),
    (9300, "Elasticsearch clustering"),
    (11211, "memcached"),
];