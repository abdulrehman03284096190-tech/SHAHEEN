# User guide

## Starting Shaheen

Run `python main.py` from the project root.

The analyzer presents packet number, time, source, destination, protocol,
length, and summary in a resizable table with persistent headers. Drag the
splitter bars to resize the packet list, decoded details, and hex/ASCII panels.
The table displays an informative empty message before a capture is loaded, for
an empty session, or when the active display filter matches no packets.

## Selecting interfaces

The app enumerates available local interfaces. For live capture, select an authorized interface and ensure the host has permission to observe traffic.

## Importing captures

Use **Import capture** in the analyzer toolbar to choose a `.pcap` or
`.pcapng` file.
Imports run in a background worker with progress feedback and cancellation. The
reader decodes sequentially and commits normalized metadata in batches of 250.
The GUI shows a database-backed page; choose 100, 200, 500, or 1,000 rows per
page and use **Previous**/**Next** to browse the full session. Pages have stable
timestamp/record-ID ordering. Cancellation preserves already committed rows
under a cancelled session. Malformed packet counts are retained; at most 100
individual warning messages are kept to bound memory.

Display filters run against the full selected session in SQLite, not just the
visible page. Supported filter terms are compiled to parameterized SQL using
the same restricted filter grammar as live display. Unsupported or malformed
expressions are shown as errors rather than silently ignored.

## Live capture and recording

1. Install Npcap with WinPcap API-compatible mode if live capture is required.
2. Select an adapter from the interface menu. The list includes available
   descriptions, IP addresses, and MAC addresses. Discovery does not guarantee
   the adapter is active or capturable.
3. Start capture explicitly. Capture filters (when provided) are distinct from
   the display filter. The current GUI does not expose a capture-filter field.
4. Pause/resume affects only packet display. Capture acquisition and active
   recording continue; packets received while display is paused are not kept in
   the visible cache.
5. Start recording to choose a `.pcap` or `.pcapng` file, then stop recording
   to finalize it. Existing files are only replaced after confirmation.
6. Stop capture, then use Import capture to reopen the recording offline.

Capture queues are bounded. The status bar distinguishes callback packets
received, parsed/accepted, metadata persisted, recorded, displayed, malformed,
and display/metadata queue drops. These are application counters, not kernel or
network packet loss measurements. Recording uses a separate synchronous write
path in the capture callback; write errors are reported and stop recording
rather than being silently ignored.

## Filters

Supported examples:

- `tcp`
- `udp`
- `dns`
- `icmp`
- `ip.src == 192.168.1.10`
- `tcp.port == 443`
- `frame.len > 1000`

These expressions are evaluated in a safe, restricted parser.

## Packet details

Click a packet row to select that persistent packet ID. Metadata is fetched from
SQLite and the detail panel shows its available frame and protocol fields. For
offline captures, raw bytes are fetched only for the selected packet and shown
as hex/ASCII. Looking up a packet far into a large capture scans the source
file from the beginning and may take time. If the source file has moved or
changed, its raw bytes may be unavailable while stored metadata remains
accessible. Live sessions need a recording to preserve raw bytes after capture
stops. The protocol tree only includes layers decoded by Shaheen's current
parser; unknown or encrypted payloads are not presented as decoded data.

## Investigation timeline and reports

1. Enter a title and select **Create investigation**.
2. Select a packet row, then choose **Add selected packet** to add its timestamp,
   summary, and packet number reference to the case timeline.
3. Choose **Export timeline** and select PDF or CSV to export the persisted case
   events.
4. Choose **Export packets CSV** to export normalized metadata for the loaded
   capture.

Investigation records and timeline events are stored in the local SQLite
database. Reports link to evidence by packet number and do not include raw
payload bytes.

Offline imports and live capture sessions also persist normalized packet
metadata in SQLite. Packet rows are associated with their capture session and
can be read in bounded pages by the storage layer. Packet payload bytes are not
stored in SQLite; for live traffic, enable recording to preserve the raw capture.
The GUI keeps only the current page of packet metadata in memory, filters use
SQLite queries, and packet CSV export streams all session metadata. To inspect
raw bytes, select a packet; loading a packet far into a large capture may take
longer because the source file is scanned to its position.

The page size is a GUI setting, while persistence batches are currently 250
records. The benchmark command and environment-specific measured results are
documented in the project README. Tracemalloc results cover Python allocations,
not total process or operating-system memory.

Frozen Windows builds store the database, captures, reports, and logs in the
current user's `%LOCALAPPDATA%\Shaheen` directory by default. Source runs retain
the project-relative paths; environment variables can override either mode.
