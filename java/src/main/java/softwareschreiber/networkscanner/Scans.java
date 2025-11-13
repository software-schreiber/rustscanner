package softwareschreiber.networkscanner;

import java.net.Inet4Address;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Future;

import org.tinylog.Logger;

class NetworkScanner {
	private static final int MAX_PORTS = 65536;

	void scanPortsFromIp(Inet4Address ipAddress, boolean scanAllPorts, ExecutorService executor) {
		List<Integer> openPorts = Collections.synchronizedList(new ArrayList<>());
		List<Future<?>> futures = new ArrayList<>();

		for (int port = 0; port < MAX_PORTS; port++) {
			if (!scanAllPorts && !CommonPorts.PORT_MAP.containsKey(port)) {
				continue;
			}

			SocketAddress socketAddress = new InetSocketAddress(ipAddress, port);
			int finalPort = port;

			futures.add(executor.submit(() -> {
				// Try to connect to the socket address with a timeout of 3 seconds
				try (Socket socket = new Socket()) {
					socket.connect(socketAddress, 3000);
					openPorts.add(finalPort);
				} catch (Exception e) {
					// Port is closed or unreachable
				}
			}));
		}

		awaitFutures(futures);

		Collections.sort(openPorts);
		Logger.info("Open ports on {}: {}", ipAddress.getHostAddress(), openPorts);
	}

	void scanPortsFromIpRange(Inet4Address startIp, Inet4Address endIp, boolean scanAllPorts, ExecutorService executorService) {
		List<Future<?>> futures = new ArrayList<>();
		int startAddrInt = ipToInt(startIp);
		int endAddrInt = ipToInt(endIp);

		for (int addrInt = startAddrInt; addrInt <= endAddrInt; addrInt++) {
			Inet4Address addr = intToIp(addrInt);

			futures.add(executorService.submit(() -> {
				if (isReachable(addr)) {
					scanPortsFromIp(addr, scanAllPorts, executorService);
				}
			}));
		}

		awaitFutures(futures);
	}

	void scanPortsFromCidr(Inet4Address subnet, int cidr, boolean scanAllPorts, ExecutorService executorService) {
		int hostBits = 32 - cidr;
		int addressCount = 1 << hostBits;

		scanPortsFromIpRange(subnet, intToIp(ipToInt(subnet) + addressCount - 1), scanAllPorts, executorService);
	}

	private int ipToInt(Inet4Address ipAddress) {
		int result = 0;

		for (byte b: ipAddress.getAddress()) {
			result = result << 8 | (b & 0xFF);
		}

		return result;
	}

	private Inet4Address intToIp(int ipAddress) {
		byte[] bytes = new byte[4];

		for (int i = 3; i >= 0; i--) {
			bytes[i] = (byte) (ipAddress & 0xFF);
			ipAddress = ipAddress >> 8;
		}

		try {
			return (Inet4Address) Inet4Address.getByAddress(bytes);
		} catch (Exception e) {
			throw new RuntimeException("Invalid IP address");
		}
	}

	private boolean isReachable(Inet4Address ipAddress) {
		try {
			return ipAddress.isReachable(3000);
		} catch (Exception e) {
			return false;
		}
	}

	private void awaitFutures(List<Future<?>> futures) {
		for (Future<?> future : futures) {
			try {
				future.get();
			} catch (Exception ignored) { }
		}
	}
}
