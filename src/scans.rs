use std::{net::{Ipv4Addr, TcpStream, ToSocketAddrs}, time::Duration};
use std::error::Error;
use std::fmt::Display;
use std::sync::mpsc;
use threadpool::ThreadPool;
use num_cpus;

const MINIMUM_THREADS: usize = 8;
const THREADS_PER_CORE: usize = 4;

pub fn scan_ports_from_ip(ip_addr: Ipv4Addr, scan_all_ports: bool) {
    let timeout = Duration::from_secs(3);
    let pool = ThreadPool::new(num_cpus::get().saturating_mul(THREADS_PER_CORE).max(MINIMUM_THREADS));
    let (tx, rx) = mpsc::channel();

    for port in 0..=u16::MAX {
        if !scan_all_ports && !COMMON_PORTS.iter().find(|&&x| x.0 == port).is_some() {
            continue;
        }

        let host_clone = ip_addr.clone();
        let tx_clone = tx.clone();
        let timeout = timeout;

		pool.execute(move || {
            let addr_str = format!("{}:{}", host_clone, port);
            match addr_str.to_socket_addrs() {
                Ok(addrs) => {
                    for addr in addrs {
                        match TcpStream::connect_timeout(&addr, timeout) {
                            Ok(_) => {
                                match tx_clone.send(port) {
                                    Ok(()) => {}
                                    Err(error) => {
                                        //println!("Failed sending to address {}: {}", addr.to_string(), error.to_string());
                                    }
                                }
                                break;
                            }
                            Err(error) => {
                                //println!("Failed to connect to address {}: {}", addr.to_string(), error.to_string());
                            }
                        }
                    }
                }
                Err(_e) => {}
            }
        });

    }

    drop(tx);
    pool.join();

    let mut open_ports: Vec<u16> = rx.iter().collect();
    open_ports.sort_unstable();
    println!("Open ports on {}: {:?}", ip_addr, open_ports);
}

pub fn scan_ports_from_ip_range(start_ip: Ipv4Addr, end_ip: Ipv4Addr, scan_all_ports: bool) {
	let start = u32::from(start_ip);
	let end = u32::from(end_ip);
    let pool = ThreadPool::new(num_cpus::get().saturating_mul(THREADS_PER_CORE).max(MINIMUM_THREADS));

    for ip_num in start..=end {
        pool.execute(move || {
			scan_ports_from_ip(Ipv4Addr::from(ip_num), scan_all_ports);
		});
	}

    pool.join();
}

pub fn scan_ports_from_subnet_cidr(subnet: Ipv4Addr, cidr: u8, scan_all_ports: bool) {
	let host_bits = 32 - cidr;
	let num_ips = 1 << host_bits;

	scan_ports_from_ip_range(subnet, Ipv4Addr::from(u32::from(subnet) + num_ips - 1), scan_all_ports);
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