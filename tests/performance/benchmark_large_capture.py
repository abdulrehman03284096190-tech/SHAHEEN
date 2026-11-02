from __future__ import annotations

import argparse
import platform
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

from scapy.all import Ether, IP, TCP
from scapy.utils import PcapWriter

PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(PROJECT_ROOT))

from capture.pcap_reader import import_capture
from database.connection import initialize_database
from database.packet_repository import PacketRepository


def benchmark(
    packet_count: int,
    *,
    trace_memory: bool = False,
) -> dict[str, float | int | None]:
    if packet_count < 1:
        raise ValueError("packet_count must be positive")

    packet = (
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="192.0.2.10", dst="198.51.100.20")
        / TCP(sport=12345, dport=443, flags="S")
    )
    with tempfile.TemporaryDirectory(prefix="shaheen-benchmark-") as temp_dir:
        root = Path(temp_dir)
        capture_path = root / "synthetic.pcap"
        database_path = str(root / "shaheen.db")

        writer = PcapWriter(str(capture_path), sync=False)
        try:
            for _ in range(packet_count):
                writer.write(packet)
        finally:
            writer.close()

        connection = initialize_database(database_path)
        repository = PacketRepository(connection)
        session_id = repository.create_session(
            source_type="pcap",
            source_path=str(capture_path),
            status="importing",
        )
        batch = []
        largest_batch = 0

        def persist(record) -> None:
            nonlocal largest_batch
            batch.append(record)
            largest_batch = max(largest_batch, len(batch))
            if len(batch) == 250:
                repository.store_packets(session_id, batch, source_path=str(capture_path))
                batch.clear()

        if trace_memory:
            tracemalloc.start()
        import_started = time.perf_counter()
        result = import_capture(
            capture_path,
            persist,
            include_raw_bytes=False,
        )
        if batch:
            repository.store_packets(session_id, batch, source_path=str(capture_path))
            batch.clear()
        import_seconds = time.perf_counter() - import_started
        peak_python_bytes = None
        if trace_memory:
            _, peak_python_bytes = tracemalloc.get_traced_memory()
            tracemalloc.stop()

        query_started = time.perf_counter()
        stored_count = repository.count_packets(session_id)
        filtered_count = repository.count_packets(session_id, "tcp.port == 443")
        first_page = repository.get_packet_page(session_id, limit=200)
        page_seconds = time.perf_counter() - query_started
        connection.close()

        if stored_count != packet_count or filtered_count != packet_count or len(first_page) != min(200, packet_count):
            raise RuntimeError("Benchmark validation failed: persisted query counts did not match")
        return {
            "packets": result.packets_read,
            "stored": stored_count,
            "filtered": filtered_count,
            "page_rows": len(first_page),
            "largest_metadata_batch": largest_batch,
            "import_seconds": round(import_seconds, 3),
            "count_and_page_seconds": round(page_seconds, 3),
            "peak_traced_python_mib": (
                round(peak_python_bytes / (1024 * 1024), 2)
                if peak_python_bytes is not None
                else None
            ),
        }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate and import synthetic PCAPs to measure Shaheen's streaming path."
    )
    parser.add_argument(
        "--packets",
        type=int,
        nargs="+",
        default=[10_000],
        help="One or more packet counts (default: 10000)",
    )
    parser.add_argument(
        "--trace-memory",
        action="store_true",
        help="Trace Python allocations (adds significant import overhead)",
    )
    args = parser.parse_args()
    print(f"Environment: {platform.platform()} | Python {platform.python_version()}")
    for count in args.packets:
        print(f"{count:,} packets: {benchmark(count, trace_memory=args.trace_memory)}")


if __name__ == "__main__":
    main()
