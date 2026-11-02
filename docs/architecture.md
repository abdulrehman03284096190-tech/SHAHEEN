# Architecture

Shaheen uses a layered architecture to keep packet acquisition, parsing, detection, AI, and reporting separate.

## Layers

1. UI: CustomTkinter windows and views.
2. Core application services: settings, bootstrap, event bus, task management.
3. Capture: Windows interface enumeration, background packet acquisition,
   bounded GUI delivery, live PCAP/PCAPNG recording, and incremental offline
   PCAP/PCAPNG import.
4. Analysis: parsing, filtering, conversation tracking, troubleshooting.
5. Detection: rule-based alerts and suppression logic.
6. AI: provider abstraction and structured response handling.
7. Database: SQLite persistence and migration-safe schema.
8. Reporting: CSV and PDF exports.

## Design principles

- Small modules and clear boundaries.
- Background worker isolation.
- Acquisition and recording do not depend on GUI display filtering or the
  bounded display queue.
- Offline capture decoding continues without a live capture provider. Offline
  imports and live sessions persist normalized packet metadata in SQLite using
  dedicated worker connections and batched writes. Unfinished sessions are
  marked interrupted at application startup.
- Structured logging.
- Validation before display or storage.

## Capture lifecycle

The user explicitly selects one discovered adapter. The live worker receives
packets with Scapy and normalizes them through the same parser as offline
imports. It writes packets to an active capture writer before attempting
non-blocking delivery to the bounded GUI queue. Queue overflow is counted as a
local display-delivery loss; it is not represented as a kernel capture drop.
Recording finalization closes the writer, allowing saved captures to be reopened
with the offline reader.

The SQLite packet store is paginated and keeps session-local packet references,
and offline analysis retains only the visible packet records in memory. Filter
expressions are compiled from the existing restricted parser into parameterized
SQLite predicates. Count and page queries do not fetch all matching records.
Pages are ordered by capture timestamp and persistent packet ID. The GUI
defaults to 200 rows and offers 100, 200, 500, or 1,000 rows per page.

CSV export streams rows from a session cursor. Packet selection resolves the
persistent ID, fetches its metadata, and loads raw bytes only for that selected
packet. Offline raw-byte lookup scans the original capture from its beginning
to the selected packet number; details remain available from SQLite if the
source file is unavailable. Live sessions without a recording have no durable
raw-byte source after capture stops.

Offline import retains only a 250-record persistence batch and the GUI's
current page. Progress updates are periodic and the UI event queue is bounded.
Cancellation stops between packet reads; successfully persisted rows remain in
a session marked cancelled. Malformed-record messages are capped at 100 while
the total malformed count is retained.

The benchmark script under `tests/performance` produces a temporary PCAP and
reports import/query duration and largest batch. `--trace-memory` reports
Python allocations via tracemalloc; it adds overhead and excludes native and
OS memory. See the README for the measured environment and results.
