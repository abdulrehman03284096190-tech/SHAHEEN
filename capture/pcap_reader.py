from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable

from scapy.all import PcapReader

from analyzer.packet_parser import PacketRecord, parse_packet


class CaptureReadError(ValueError):
    """The selected file is not a readable capture or ended unexpectedly."""


MAX_IMPORT_WARNINGS = 100


@dataclass(frozen=True)
class ImportProgress:
    packets_read: int
    bytes_read: int
    total_bytes: int


@dataclass
class ImportResult:
    packets_read: int = 0
    malformed_packets: int = 0
    bytes_read: int = 0
    total_bytes: int = 0
    cancelled: bool = False
    warnings: list[str] = field(default_factory=list)


def _validate_capture_path(path: str | Path) -> Path:
    file_path = Path(path)
    if not file_path.exists():
        raise FileNotFoundError(f"Capture file not found: {file_path}")
    if not file_path.is_file():
        raise CaptureReadError(f"Capture path is not a file: {file_path}")
    if file_path.suffix.lower() not in {".pcap", ".pcapng", ".cap"}:
        raise CaptureReadError(f"Unsupported capture format: {file_path.suffix or 'unknown'}")
    if file_path.stat().st_size == 0:
        raise CaptureReadError("Capture file is empty")
    return file_path


def import_capture(
    path: str | Path,
    on_packet: Callable[[PacketRecord], None],
    *,
    cancel_event: threading.Event | None = None,
    on_progress: Callable[[ImportProgress], None] | None = None,
    progress_interval: int = 250,
    include_raw_bytes: bool = True,
) -> ImportResult:
    """Read one packet at a time, reporting malformed records and progress."""
    file_path = _validate_capture_path(path)
    result = ImportResult(total_bytes=file_path.stat().st_size)
    if progress_interval < 1:
        raise ValueError("progress_interval must be greater than zero")

    try:
        reader = PcapReader(str(file_path))
    except Exception as exc:
        raise CaptureReadError(f"Unable to open capture file: {exc}") from exc

    try:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                result.cancelled = True
                break
            try:
                packet = reader.read_packet()
            except EOFError:
                break
            except Exception as exc:
                raise CaptureReadError(
                    f"Capture read failed after {result.packets_read} packets: {exc}"
                ) from exc

            if packet is None:
                break

            packet_number = result.packets_read + result.malformed_packets + 1
            try:
                record = parse_packet(
                    packet,
                    packet_number,
                    include_raw_bytes=include_raw_bytes,
                )
            except Exception as exc:
                result.malformed_packets += 1
                if len(result.warnings) < MAX_IMPORT_WARNINGS:
                    result.warnings.append(
                        f"Packet {packet_number} could not be decoded: {exc}"
                    )
            else:
                on_packet(record)
                result.packets_read += 1

            try:
                result.bytes_read = reader.f.tell()
            except (AttributeError, OSError):
                result.bytes_read = min(result.total_bytes, result.bytes_read)
            if on_progress and (
                packet_number % progress_interval == 0 or packet is None
            ):
                on_progress(
                    ImportProgress(
                        packets_read=result.packets_read,
                        bytes_read=result.bytes_read,
                        total_bytes=result.total_bytes,
                    )
                )
    finally:
        reader.close()

    if on_progress:
        on_progress(
            ImportProgress(
                packets_read=result.packets_read,
                bytes_read=result.bytes_read,
                total_bytes=result.total_bytes,
            )
        )
    return result


def read_pcap_file(path: str) -> list[PacketRecord]:
    packets: list[PacketRecord] = []
    import_capture(path, packets.append)
    return packets


def read_pcapng_file(path: str) -> list[PacketRecord]:
    return read_pcap_file(path)


def read_pcap_stream(path: str) -> Iterable[PacketRecord]:
    file_path = _validate_capture_path(path)
    try:
        with PcapReader(str(file_path)) as reader:
            packet_number = 0
            while True:
                try:
                    packet = reader.read_packet()
                except EOFError:
                    return
                except Exception as exc:
                    raise CaptureReadError(
                        f"Capture read failed after {packet_number} packets: {exc}"
                    ) from exc
                if packet is None:
                    return
                packet_number += 1
                try:
                    yield parse_packet(packet, packet_number)
                except Exception as exc:
                    raise CaptureReadError(
                        f"Packet {packet_number} could not be decoded: {exc}"
                    ) from exc
    except CaptureReadError:
        raise
    except Exception as exc:
        raise CaptureReadError(f"Unable to read capture stream: {exc}") from exc


def read_packet_at(
    path: str | Path,
    packet_number: int,
    *,
    cancel_event: threading.Event | None = None,
) -> PacketRecord:
    """Read one packet by its one-based capture position without retaining others."""
    if packet_number < 1:
        raise ValueError("packet_number must be at least one")
    file_path = _validate_capture_path(path)
    try:
        with PcapReader(str(file_path)) as reader:
            for current_number in range(1, packet_number + 1):
                if cancel_event is not None and cancel_event.is_set():
                    raise CaptureReadError("Packet lookup cancelled")
                try:
                    packet = reader.read_packet()
                except EOFError as exc:
                    raise CaptureReadError(
                        f"Packet {packet_number} is beyond the end of the capture"
                    ) from exc
                except Exception as exc:
                    raise CaptureReadError(
                        f"Capture read failed at packet {current_number}: {exc}"
                    ) from exc
                if packet is None:
                    raise CaptureReadError(
                        f"Packet {packet_number} is beyond the end of the capture"
                    )
                if current_number == packet_number:
                    try:
                        return parse_packet(packet, current_number)
                    except Exception as exc:
                        raise CaptureReadError(
                            f"Packet {packet_number} could not be decoded: {exc}"
                        ) from exc
    except CaptureReadError:
        raise
    except Exception as exc:
        raise CaptureReadError(f"Unable to read capture packet: {exc}") from exc
    raise CaptureReadError(f"Packet {packet_number} could not be read")
