package softwareschreiber.networkscanner;

import java.net.Inet4Address;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.tinylog.Logger;

public class Main {
	public static void main(String[] args) throws Exception {
		NetworkScanner scanner = new NetworkScanner();

		// ExecutorService executorService = Executors.newVirtualThreadPerTaskExecutor();
		ExecutorService executorService = Executors.newFixedThreadPool(20_000, Thread.ofVirtual().factory());

		long start = System.currentTimeMillis();

		scanner.scanPortsFromIpRange(
				(Inet4Address) Inet4Address.getByName("192.168.178.0"),
				(Inet4Address) Inet4Address.getByName("192.168.178.100"),
				true,
				executorService);

		long duration = System.currentTimeMillis() - start;
		Logger.info("Scanning completed in {} ms", duration);
	}
}
