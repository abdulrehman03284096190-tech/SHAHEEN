# Limitations

- Full Wireshark parity is not implemented.
- Live capture requires Scapy's libpcap/Npcap provider, a capturable Windows
  adapter, and appropriate permissions. Real capture has not been verified in
  this development environment because `wpcap.dll`/Npcap was not found.
- Capture enumeration does not establish adapter link state or capture
  availability.
- The live display queue is bounded and counts its own overflow, but this count
  is not a measurement of kernel/Npcap drops. Recording writes synchronously in
  the packet callback and can affect acquisition performance under sustained
  load.
- Display pause does not stop acquisition or recording; packets acquired while
  paused are omitted from the GUI's live display cache.
- Offline packet metadata is stored incrementally in SQLite, and the repository
  supports bounded pagination. The GUI retains one page (100, 200, 500, or
  1,000 lightweight records); filters run as SQL and CSV export streams rows.
  Raw bytes are loaded for the selected packet only. This bounds decoded GUI
  records, not SQLite disk use, Scapy/native memory, or total time for arbitrary
  captures.
- Loading raw bytes for a selected offline packet scans the capture from its
  beginning to that packet, so selecting a packet late in a very large file can
  take time.
- Live packet metadata storage uses a bounded queue. If storage cannot keep up,
  dropped metadata is counted and recorded in the session statistics; raw
  recording is a separate workflow.
- Offline raw bytes are read from the original file on demand, using a sequential
  scan to the packet number. Moved/changed files can make the payload unavailable.
  Live packet payloads are not persisted in the metadata database; recording is
  required to retain the raw capture after capture stops.
- SQLite filtering covers the fields in the existing safe display-filter
  grammar. It does not provide free-text search or filters over arbitrary
  application-layer details.
- The recorded 10k/100k timings and traced Python-allocation result are
  environment-specific; tracemalloc does not measure native or OS buffers.
  Consult the README and rerun the benchmark on target hardware.
- Full TLS decryption requires proper keys and infrastructure.
- AI analysis is optional and must be treated as advisory output, not fact.
- No checked-in PyInstaller spec or installer definition exists. Frozen builds
  use per-user application data paths, but the executable command documented in
  the README still requires release smoke testing outside the source tree.
