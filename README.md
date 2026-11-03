# Shaheen

Shaheen is an AI-assisted network traffic analysis and security monitoring desktop application for Windows. It provides packet import, protocol inspection, filtering, basic investigation workflows, alerting, and reporting in a modular Python architecture.

## Goals

- Live capture support on compatible Windows interfaces.
- Offline PCAP/PCAPNG analysis.
- Packet filtering and protocol analysis.
- Threat detection using deterministic rules.
- AI assistance for summaries and explanations when configured.
- SQLite-backed investigation timelines and evidence references.
- Protocol-tree packet details, packet CSV export, and investigation PDF/CSV reports.

## Stack

- Python 3.12+
- CustomTkinter
- Scapy
- SQLite
- pandas, matplotlib
- ReportLab
- Pytest
- PyInstaller

## Project structure

```text
Shaheen/
├── main.py
├── requirements.txt
├── requirements-dev.txt
├── pyproject.toml
├── .env.example
├── .gitignore
├── README.md
├── config/
├── core/
├── gui/
├── capture/
├── analyzer/
├── detection/
├── ai/
├── database/
├── investigations/
├── reports/
├── security/
├── tests/
├── docs/
├── data/
├── captures/
├── reports_output/
├── logs/
└── .venv/
```

## Setup

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

## Run

```powershell
python main.py
```

## Windows distribution

Source runs keep the database, captures, reports, and logs under the project
directory by default. A frozen PyInstaller build stores writable data under
`%LOCALAPPDATA%\Shaheen` (or `%APPDATA%\Shaheen` if LocalAppData is not
defined), including a per-user configuration directory; each data path can
still be overridden with its corresponding environment variable.

The 64-bit Windows release specification, Inno Setup installer, build steps,
and installation/data-preservation guidance are maintained in
[`SHAHEEN_RELEASE`](./SHAHEEN_RELEASE/README_INSTALLATION.md). Build the
standalone application with `SHAHEEN_RELEASE\SHAHEEN.spec` and compile the
installer with the included `SHAHEEN_Setup.iss`. Live Windows capture requires
separately installed Npcap; it is not redistributed with SHAHEEN.

## Testing

```powershell
pytest -q
```

## Investigation and evidence exports

Select a packet in the packet list, enter an investigation title, and choose
**Create investigation**. With that investigation active, choose **Add selected
packet** to persist a timestamped packet reference and its normalized metadata
in SQLite. The event timeline is retained across application restarts.

Use **Export packets CSV** for the loaded packet metadata. Use **Export timeline**
to save the active investigation as PDF or CSV. The PDF report contains the
investigation status, notes, timestamps, event summaries, and evidence references;
it does not embed raw packet payloads.

Packet details include a derived protocol tree and a hex/ASCII view from the
selected packet's bytes. These are inspection views, not a complete protocol
dissector or forensic chain-of-custody mechanism.

Offline imports now read packets incrementally on a background worker and offer
progress and cancellation. The GUI reads only the current database-backed page
(200 rows by default; choose 100, 200, 500, or 1,000).
Normalized packet metadata from offline imports and live captures is also
persisted in SQLite by session, with batched background writes and paginated
repository access. Filters compile to parameterized SQL for the supported
display-filter grammar; unsupported filters are reported. CSV export streams
database rows, and packet details and raw bytes are fetched only for the
selected persistent record. Raw-byte lookup scans the source capture to that
packet's position.

Run the reproducible synthetic-capture benchmark with:

```powershell
python tests\performance\benchmark_large_capture.py --packets 10000 100000
python tests\performance\benchmark_large_capture.py --packets 10000 --trace-memory
```

On Windows 11 (build 22621), Python 3.15.0, and an Intel Core i7-7500U
2.70 GHz system with 7.9 GiB RAM, the latest measured import times were
4.801 s for 10,000 packets and 65.726 s for 100,000 packets. Count/filter and
first-page queries took 0.017 s and 0.224 s, respectively. A separate
10,000-packet tracemalloc run observed a 0.94 MiB peak of traced Python
allocations; tracing materially slows the benchmark and does not include native
Scapy/SQLite or OS buffers. A sampled CPU profile showed packet decoding and
batched persistence as the main application-level costs. These are
environment-specific measurements, not guarantees. Each import batch was
capped at 250 records and the page contained 200 rows.

The GUI's decoded-record memory is bounded by the current page; this does not
promise unlimited capture size or bounded storage/disk usage. The legacy
`read_pcap_file` convenience API intentionally returns a complete list; use
`import_capture`/the GUI for incremental processing. See
[docs/implementation_plan.md](docs/implementation_plan.md) for verified scope
and remaining work.

## Live capture and recording

The capture screen discovers Windows adapters and requires an explicit
selection. Adapter discovery is not a capture test. Live capture requires
Npcap, a Scapy capture provider, and sufficient rights for the chosen adapter.
Shaheen does not elevate itself and does not silently select another adapter.

Start capture, optionally pause/resume the display, and use **Start recording**
to save genuine captured packets as `.pcap` or `.pcapng`. Stop recording
finalizes the file; use **Import capture** afterward to analyze it offline.
Recording runs in the capture callback independently of the bounded GUI packet
queue and display filter. The status shows received, written, delivered, and
local display-queue dropped counts. It cannot report Npcap/kernel drops unless
the backend exposes trustworthy statistics.

The current environment has Scapy installed but no Npcap `wpcap.dll` provider,
so genuine live capture has **not been verified** here. Offline import remains
available.

## Notes

- This implementation emphasizes a working, testable foundation and a modular architecture.
- Live packet capture requires the appropriate Windows capture driver and permissions.
- AI features are deliberately mocked unless configured with a valid external provider.
