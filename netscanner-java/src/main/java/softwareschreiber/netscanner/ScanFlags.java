package softwareschreiber.netscanner;

public record ScanFlags(boolean scanAllPorts, boolean pingProhibited, int maxThreads) {
}
