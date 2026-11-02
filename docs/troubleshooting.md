# Troubleshooting

## Common issues

- Missing dependencies: install `requirements.txt`.
- GUI fails to open: ensure customtkinter is installed and a GUI session is available.
- Live capture reports no provider: install Npcap with WinPcap API-compatible
  mode, restart Shaheen, and verify that Scapy can use its libpcap provider.
- Live capture fails on one adapter: check the selected adapter and permissions.
  Shaheen does not switch adapters automatically; successful enumeration alone
  does not prove that capture will work.
- Capture permission denied: use an account allowed by the Npcap installation.
  Shaheen does not elevate itself.
- Recording cannot start: ensure live capture is running, choose `.pcap` or
  `.pcapng`, and select a new filename or explicitly confirm replacing an
  existing file.
- Recording reports a write/finalization error: stop capture when possible and
  check the output path's permissions and available disk space. A failed
  recording is not reported as successfully saved.
- Import reports a database/write error: check that the database directory is
  writable and that sufficient disk space is available. The session is marked
  failed where possible; already committed packet batches remain available.
- A filter returns no records or reports an unsupported term: verify the
  expression against the supported examples and fields in the user guide.
  Shaheen rejects unsupported expressions rather than evaluating them as code.
- Packet metadata appears but hex bytes are unavailable: the source capture
  must still exist at its original path and match the imported record. Raw-byte
  lookup scans from the start of the file, so a late packet in a large capture
  may take longer to load. Enable live recording to preserve capture bytes.
- Capture metadata is missing after an interrupted shutdown: restart recovery
  marks unfinished sessions as interrupted. Completed write batches remain;
  packets not committed before interruption cannot be recovered from SQLite.
- No traffic: ensure the selected interface sees traffic and the user has the correct privileges.
