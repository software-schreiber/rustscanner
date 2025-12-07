
pub struct ScanFlags {
	pub scan_all_ports: bool,
	pub ping_prohibited: bool,
	pub max_threads: usize,
}

impl ScanFlags {
	pub fn new(scan_all_ports: bool, ping_prohibited: bool, max_threads: usize) -> ScanFlags {
		ScanFlags {
			scan_all_ports,
			ping_prohibited,
			max_threads,
		}
	}

	pub fn clone(&self) -> ScanFlags {
		ScanFlags::new(self.scan_all_ports.clone(), self.ping_prohibited.clone(), self.max_threads.clone())
	}
}
