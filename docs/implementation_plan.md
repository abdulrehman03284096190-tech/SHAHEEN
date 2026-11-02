# Shaheen implementation plan

This plan tracks verified work in the existing project. A planned item is not
considered complete until its implementation and tests exist.

## Current baseline

- Python project with CustomTkinter, Scapy, SQLite, ReportLab, and pytest.
- Existing safe display-filter parser and normalized `PacketRecord`.
- Existing live capture, packet detail, conversation, detection, investigation,
  and export modules.
- Baseline suite before this work: `python -m pytest -q` — 15 passed.
- Real Windows/Npcap capture and interactive GUI operation have not been
  manually verified in this environment.

## Work sequence

1. **Stability and offline import**
   - Preserve the normalized packet model and filter behavior.
   - Read captures incrementally instead of using whole-file `rdpcap`.
   - Report malformed/truncated input, progress, and cancellation.
   - Move GUI imports off the Tk event thread and cap packet-list rendering.
2. **Live capture reliability**
   - Remove fabricated interface fallbacks.
   - Bound display buffering, isolate recording from display backpressure,
     surface writer errors, and close capture resources on shutdown.
   - Verify against a real authorized Windows interface separately.
3. **Packet analysis**
   - Add evidence-based link/network/transport/application dissection,
     documented filter-field support, conversations, and statistics.
4. **Investigation and defensive monitoring**
   - Persist capture-session identity, findings, timeline references, and
     configurable rule thresholds with traceable packet references.
5. **Reporting and release**
   - Validate reports against real imported fixtures, document privacy and
     limits, then test Windows packaging independently.

## Immediate implementation slice

Implement streaming offline import with cancellation and progress, preserving
the current packet representation. Add worker-driven UI integration and tests
for valid, malformed, and cancelled imports. Do not mark live capture or
large-file memory limits as verified until separately tested.

## Latest verified update

- Offline import reads one Scapy packet at a time through `PcapReader`.
- Import supports progress callbacks, cancellation, decode-warning counts, and
  explicit errors for invalid/unsupported capture files.
- Windows interface discovery reports actual adapter descriptions, addresses,
  MAC addresses, and loopback/virtual hints. Enumeration failure is explicit;
  no fake interface fallback is returned.
- The GUI requires explicit adapter selection and provides refresh, capture,
  display pause/resume, and recording controls.
- Live capture uses a bounded packet queue; recordings are written before
  non-blocking display delivery, so display queue overflow does not discard the
  recording path.
- PCAP and PCAPNG recording are finalized through Scapy writers and existing
  offline readers. Existing output paths are refused unless the user confirms
  replacement in the GUI.
- Provider, adapter, permission, and recording errors are surfaced. No real
  Windows capture has been verified: the active Python 3.15 environment lacks
  the Npcap `wpcap.dll` provider.
- Automated tests cover provider absence, discovery failures, bounded queue
  overflow, overwrite protection, mocked capture lifecycle, timestamp
  preservation, and recorded PCAPNG reopening.
- Latest suite after database-backed paging and SQL filtering:
  `python -m pytest -q` — 40 passed.

## Remaining work / limitations

- Offline imports now persist 250-record batches; the GUI loads a configurable
  100/200/500/1,000-row page with stable timestamp/ID ordering.
- The safe display-filter grammar compiles to parameterized SQLite queries;
  filtered counts and page queries do not load all matching records.
- Packet details are fetched by persistent record ID. Offline raw bytes are
  loaded only for the selected packet, from the original capture file.
- Packet CSV exports stream SQLite rows. A 10k/100k synthetic PCAP benchmark
  and GUI paging/filter/selection smoke tests have been run; see README for
  measured results and their limitations.
- Live recording writes synchronously inside the Scapy packet callback, which
  may reduce capture throughput. No live hardware performance test has been
  run.
- Adapter discovery does not report link state reliably, and one discovered
  adapter may still be unavailable to the capture backend.
- Free-text packet search and incremental session statistics are not
  implemented.
- Real Windows/Npcap validation is still required.
- The current parser is not a full Wireshark/TShark dissector.
- Installation metadata, dependency pinning, and packaged Windows validation
  remain release work.

## Recommended next stage

Add a capture-session browser so users can reopen previously imported captures
and live recordings without reimporting them. Include session metadata,
database-backed packet paging/filtering, and per-session summary statistics;
keep raw-byte access tied to the selected source capture and clearly report
when that file is unavailable.
