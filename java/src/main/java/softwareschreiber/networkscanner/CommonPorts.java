package softwareschreiber.networkscanner;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public enum CommonPorts {
	FTP_DATA(20, "FTP-data"),
	FTP(21, "FTP"),
	SSH(22, "SSH"),
	TELNET(23, "Telnet"),
	SMTP(25, "SMTP"),
	DNS(53, "DNS"),
	DHCP_SERVER(67, "DHCP (server)"),
	DHCP_CLIENT(68, "DHCP (client)"),
	TFTP(69, "TFTP"),
	HTTP(80, "HTTP"),
	KERBEROS(88, "Kerberos"),
	POP3(110, "POP3"),
	RPCBIND_PORTMAPPER(111, "rpcbind / portmapper"),
	NTP(123, "NTP"),
	MS_RPC_DCOM(135, "MS RPC / DCOM"),
	NETBIOS_NAME(137, "NetBIOS Name"),
	NETBIOS_DATAGRAM(138, "NetBIOS Datagram"),
	NETBIOS_SESSION_SMB_OLDER(139, "NetBIOS Session / SMB (older)"),
	IMAP(143, "IMAP"),
	SNMP(161, "SNMP"),
	SNMP_TRAP(162, "SNMP trap"),
	BGP(179, "BGP"),
	LDAP(389, "LDAP"),
	HTTPS(443, "HTTPS"),
	SMB_MICROSOFT_DS(445, "SMB / Microsoft-DS"),
	SMTPS_DEPRECATED(465, "SMTPS (deprecated)"),
	REXEC(512, "rexec"),
	RLOGIN(513, "rlogin"),
	SYSLOG_RSH(514, "syslog / rsh"),
	LPD_PRINTER(515, "LPD / printer"),
	AFP(548, "AFP (Apple Filing Protocol)"),
	IPP_PRINTING(631, "IPP (printing)"),
	LDAPS(636, "LDAPS"),
	IMAPS(993, "IMAPS"),
	POP3S(995, "POP3S"),
	SOCKS_PROXY(1080, "SOCKS (proxy)"),
	OPENVPN(1194, "OpenVPN"),
	MSSQL(1433, "MSSQL"),
	MSSQL_UDP(1434, "MSSQL (UDP)"),
	ORACLE_DB_LISTENER(1521, "Oracle DB (listener)"),
	PPTP(1723, "PPTP"),
	NFS(2049, "NFS"),
	CPANEL_HTTP(2082, "cPanel (HTTP)"),
	CPANEL_HTTPS(2083, "cPanel (HTTPS)"),
	DOCKER_API_UNSECURED(2375, "Docker API (unsecured)"),
	DOCKER_API_TLS(2376, "Docker API (TLS)"),
	MONGODB(27017, "MongoDB"),
	DEV_SERVERS_WEB_APPS(3000, "Dev servers / web apps"),
	MYSQL_MARIADB(3306, "MySQL / MariaDB"),
	RDP(3389, "RDP (Windows Remote Desktop)"),
	EXAMPLE_DB_ABUSE_PORT(37017, "Example DB abuse port (seen in the wild)"),
	DEV_UPNP_ADMIN_UIS(5000, "Dev / UPnP / admin UIs"),
	SIP(5060, "SIP (VoIP)"),
	SIP_TLS(5061, "SIP TLS"),
	POSTGRESQL(5432, "PostgreSQL"),
	APP_SPECIFIC_5560(5560, "App-specific (often seen in networks)"),
	VNC(5900, "VNC"),
	REDIS(6379, "Redis"),
	ALTERNATE_HTTP_8000(8000, "Alternate HTTP / admin"),
	PROXMOX_VE_WEB_GUI(8006, "Proxmox VE web GUI"),
	ALTERNATE_HTTP_8008(8008, "Alternate HTTP"),
	ALTERNATE_HTTP_PROXY_8080(8080, "Alternate HTTP / proxy"),
	HTTPS_ALT_ADMIN_8443(8443, "HTTPS-alt / admin"),
	DEV_ADMIN_9000(9000, "Dev/admin (e.g. php-fpm, dev UIs)"),
	ELASTICSEARCH_HTTP(9200, "Elasticsearch HTTP"),
	ELASTICSEARCH_CLUSTERING(9300, "Elasticsearch clustering"),
	MEMCACHED(11211, "memcached");

	private final int port;
	private final String description;

	CommonPorts(int port, String description) {
		this.port = port;
		this.description = description;
	}

	public int getPort() {
		return port;
	}

	public String getDescription() {
		return description;
	}

	@Override
	public String toString() {
		return port + " - " + description;
	}

	public static final Map<Integer, CommonPorts> PORT_MAP;

	static {
		Map<Integer, CommonPorts> map = new HashMap<>();

		for (CommonPorts cp : values()) {
			map.put(cp.port, cp);
		}

		PORT_MAP = Collections.unmodifiableMap(map);
	}

	public static CommonPorts fromPort(int port) {
		return PORT_MAP.get(port);
	}
}
