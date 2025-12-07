package softwareschreiber.netscanner;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.tinylog.Logger;

public class Main {
	private static final int DEFAULT_MAX_THREADS = 512;

	static void main(String[] args) throws Exception {
		if (args.length < 1) {
			Logger.error("There should be at least one argument. Type 'help' to get extended information");
			return;
		}

		List<String> argList = Arrays.asList(args);
		String firstArgument = argList.getFirst();

		if (firstArgument.equals("help") || firstArgument.equals("?")) {
			Logger.info("Syntax:   netscanner <usage> [options]");
			Logger.info("");
			Logger.info("Usage:    help                            Shows this text");
			Logger.info("          this                            Scans important ports of the current device");
			Logger.info("          device <IP>                     Scans important ports of the given IP");
			Logger.info("          range <Start_IP> <End_IP>       Scans important ports of all IPs in the range [Start; End]");
			Logger.info("          subnet <IP> <CIDR>              Scans important ports of in subnet");
			Logger.info("Options:  -a                              Scan all ports (time consuming)");
			Logger.info("          -t <Number>                     Set the maximum number of parallel connections while scanning (default: {})", DEFAULT_MAX_THREADS);
			Logger.info("          -p                              Prohibit the use of pinging (takes more time)");
			System.exit(0);
		}

		long startTime = System.currentTimeMillis();
		ScanFlags flags = new ScanFlags(
				argList.contains("-a"),
				argList.contains("-p"),
				argList.contains("-t")
					? Integer.parseInt(argList.get(argList.indexOf("-t") + 1))
					: DEFAULT_MAX_THREADS);

		ExecutorService threadPool = Executors.newFixedThreadPool(flags.maxThreads(), Thread.ofVirtual().factory());
		NetworkScanner scanner = new NetworkScanner();

		switch (firstArgument) {
			case "this" -> {
				scanner.scanPortsFromIp(
						InetAddress.getLocalHost(),
						flags,
						threadPool);
			}
			case "device" -> {
				if (argList.size() < 2) {
					Logger.error("The argument 'device' requires one more argument. Type 'help' to get extended information");
					System.exit(1);
				}

				scanner.scanPortsFromIp(
						InetAddress.getByName(argList.get(1)),
						flags,
						threadPool);
			}
			case "range" -> {
				if (argList.size() < 3) {
					Logger.error("The argument 'range' requires two more arguments. Type 'help' to get extended information");
					System.exit(1);
				}

				scanner.scanPortsFromIpRange(
						(Inet4Address) Inet4Address.getByName(argList.get(1)),
						(Inet4Address) Inet4Address.getByName(argList.get(2)),
						flags,
						threadPool);
			}
			case "subnet" -> {
				if (argList.size() < 3) {
					Logger.error("The argument 'subnet' requires two more arguments. Type 'help' to get extended information");
					System.exit(1);
				}

				scanner.scanPortsFromCidr(
						(Inet4Address) Inet4Address.getByName(argList.get(1)),
						Integer.parseInt(argList.get(2)),
						flags,
						threadPool);
			}
			default -> {
				Logger.error("Unknown argument '{}'. Type 'help' or '?' to see available options", firstArgument);
				System.exit(1);
			}
		}

		long duration = System.currentTimeMillis() - startTime;
		Logger.info("Scanning completed in {} ms", duration);
	}
}
