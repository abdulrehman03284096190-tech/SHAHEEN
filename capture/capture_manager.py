from __future__ import annotations

import queue
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from scapy.all import PcapNgWriter, PcapWriter, conf, sniff

from analyzer.filter_engine import evaluate_filter
from analyzer.packet_parser import PacketRecord, parse_packet
from capture.interface_manager import InterfaceManager
from core.exceptions import CaptureError


@dataclass(frozen=True)
class CaptureStats:
    packets_received: int
    packets_accepted: int
    packets_recorded: int
    packets_delivered: int
    packets_dropped_from_display_queue: int
    packets_dropped_from_storage_queue: int
    malformed_packets: int
    recording: bool


class CaptureManager:
    def __init__(
        self,
        *,
        queue_limit: int = 1000,
        sniff_backend: Callable[..., Any] | None = None,
    ) -> None:
        if queue_limit < 1:
            raise ValueError("queue_limit must be greater than zero")
        self.capture_thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.packet_queue: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=queue_limit)
        self._control_events: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=32)
        self.interface_name: str | None = None
        self.capture_filter: str | None = None
        self.record_path: str | None = None
        self.session_id: int | None = None
        self.writer: PcapWriter | PcapNgWriter | None = None
        self._recording_file = None
        self.last_recording_path: str | None = None
        self._packet_number = 0
        self._lock = threading.RLock()
        self._sniff = sniff_backend or sniff
        self._packets_received = 0
        self._packets_accepted = 0
        self._packets_recorded = 0
        self._packets_delivered = 0
        self._display_queue_drops = 0
        self._storage_queue_drops = 0
        self._malformed_packets = 0
        self.last_error: str | None = None
        self.last_recording_error: str | None = None
        self.packet_sink: Callable[[PacketRecord], bool] | None = None

    @property
    def is_running(self) -> bool:
        return bool(self.capture_thread and self.capture_thread.is_alive())

    @property
    def stats(self) -> CaptureStats:
        with self._lock:
            return CaptureStats(
                packets_received=self._packets_received,
                packets_accepted=self._packets_accepted,
                packets_recorded=self._packets_recorded,
                packets_delivered=self._packets_delivered,
                packets_dropped_from_display_queue=self._display_queue_drops,
                packets_dropped_from_storage_queue=self._storage_queue_drops,
                malformed_packets=self._malformed_packets,
                recording=self.writer is not None,
            )

    def get_interfaces(self):
        return InterfaceManager.list_interfaces()

    @staticmethod
    def capture_provider_status() -> tuple[bool, str]:
        if not conf.use_pcap:
            return (
                False,
                "Scapy has no libpcap/Npcap provider. Install Npcap with WinPcap API-compatible mode, then restart Shaheen.",
            )
        return True, "Scapy libpcap provider is available; actual capture still depends on interface and permissions."

    def start_capture(
        self,
        interface_name: str,
        *,
        capture_filter: str | None = None,
        record_path: str | None = None,
    ) -> None:
        if not interface_name:
            raise CaptureError("Select a network interface before starting capture.")
        if self.is_running:
            raise CaptureError("Capture is already running")
        available, reason = self.capture_provider_status()
        if not available:
            raise CaptureError(reason)

        self.stop_event = threading.Event()
        self.interface_name = interface_name
        self.capture_filter = capture_filter or None
        self.record_path = None
        self.last_recording_path = None
        self._packet_number = 0
        self.last_error = None
        self.last_recording_error = None
        with self._lock:
            self._packets_received = 0
            self._packets_accepted = 0
            self._packets_recorded = 0
            self._packets_delivered = 0
            self._display_queue_drops = 0
            self._storage_queue_drops = 0
            self._malformed_packets = 0
        self._clear_queue(self.packet_queue)
        self._clear_queue(self._control_events)

        if record_path:
            output, file_handle, writer = self._create_recording_writer(record_path)
            self.record_path = str(output)
            self.last_recording_path = str(output)
            self._recording_file = file_handle
            self.writer = writer
        self.capture_thread = threading.Thread(
            target=self._capture_loop,
            name="shaheen-capture",
            daemon=True,
        )
        try:
            self.capture_thread.start()
        except Exception:
            self.stop_event.set()
            try:
                self.stop_recording()
            finally:
                self.capture_thread = None
            raise

    @staticmethod
    def _clear_queue(target: queue.Queue) -> None:
        while True:
            try:
                target.get_nowait()
            except queue.Empty:
                return

    @staticmethod
    def _create_recording_writer(
        path: str,
        *,
        overwrite: bool = False,
    ) -> tuple[Path, Any, PcapWriter | PcapNgWriter]:
        output = Path(path)
        if output.suffix.lower() not in {".pcap", ".pcapng"}:
            raise CaptureError("Recording filename must end in .pcap or .pcapng")
        if output.exists() and not overwrite:
            raise CaptureError(f"Refusing to overwrite existing recording: {output}")
        output.parent.mkdir(parents=True, exist_ok=True)

        created_exclusively = False
        try:
            if not overwrite:
                with output.open("xb"):
                    created_exclusively = True
            writer_type = PcapNgWriter if output.suffix.lower() == ".pcapng" else PcapWriter
            writer = writer_type(str(output))
            if hasattr(writer, "sync"):
                writer.sync = True
        except Exception as exc:
            if created_exclusively:
                try:
                    output.unlink()
                except OSError:
                    pass
            raise CaptureError(f"Unable to create recording file: {exc}") from exc
        return output, None, writer

    def start_recording(self, path: str, *, overwrite: bool = False) -> None:
        with self._lock:
            if self.writer is not None:
                raise CaptureError("Recording is already active")
            if not self.is_running:
                raise CaptureError("Start packet capture before recording")

        output, file_handle, writer = self._create_recording_writer(path, overwrite=overwrite)
        with self._lock:
            if self.writer is not None or not self.is_running:
                writer.close()
                raise CaptureError("Capture state changed before recording could start")
            self._recording_file = file_handle
            self.writer = writer
            self.record_path = str(output)
            self.last_recording_path = str(output)
            self.last_recording_error = None

    def stop_recording(self) -> str | None:
        with self._lock:
            writer = self.writer
            output_path = self.record_path
            self.writer = None
            self._recording_file = None
            self.record_path = None
        if writer is not None:
            try:
                writer.close()
            except Exception as exc:
                self.last_recording_error = f"Unable to finalize recording: {exc}"
                self._publish_event("recording_error", self.last_recording_error)
                raise CaptureError(self.last_recording_error) from exc
        return output_path

    def stop_capture(self, timeout: float = 5.0) -> None:
        self.stop_event.set()
        try:
            self.stop_recording()
        finally:
            thread = self.capture_thread
            if thread is not None:
                thread.join(timeout=timeout)
                if thread.is_alive():
                    raise CaptureError(
                        "Capture worker did not stop in time; capture resources may still be active."
                    )
                self.capture_thread = None

    def _publish_event(self, event_type: str, payload: Any) -> None:
        if event_type != "packet":
            try:
                self._control_events.put_nowait((event_type, payload))
            except queue.Full:
                self.last_error = str(payload)
            return
        try:
            self.packet_queue.put_nowait((event_type, payload))
        except queue.Full:
            with self._lock:
                self._display_queue_drops += 1

    def _on_packet(self, raw_packet: Any) -> None:
        if self.stop_event.is_set():
            return
        with self._lock:
            self._packets_received += 1
            self._packet_number += 1
            packet_number = self._packet_number

            if self.writer is not None:
                try:
                    self.writer.write(raw_packet)
                    self._packets_recorded += 1
                except Exception as exc:
                    self.last_recording_error = f"Recording write failed: {exc}"
                    failed_writer = self.writer
                    self.writer = None
                    self._recording_file = None
                    try:
                        failed_writer.close()
                    except Exception:
                        pass
                    self._publish_event("recording_error", self.last_recording_error)

        try:
            record = parse_packet(raw_packet, packet_number)
        except Exception as exc:
            with self._lock:
                self._malformed_packets += 1
            self._publish_event("packet_error", (packet_number, str(exc)))
            return
        with self._lock:
            self._packets_accepted += 1
        record.session_id = self.session_id
        if self.packet_sink is not None:
            try:
                if not self.packet_sink(record):
                    with self._lock:
                        self._storage_queue_drops += 1
                        dropped = self._storage_queue_drops
                    if dropped == 1:
                        self._publish_event(
                            "storage_error",
                            "Packet metadata storage queue is full; some packet summaries may not persist.",
                        )
            except Exception as exc:
                with self._lock:
                    self._storage_queue_drops += 1
                self._publish_event("storage_error", str(exc))
        self._publish_event("packet", record)

    def _capture_loop(self) -> None:
        try:
            while not self.stop_event.is_set():
                self._sniff(
                    iface=self.interface_name,
                    filter=self.capture_filter,
                    prn=self._on_packet,
                    store=False,
                    timeout=0.25,
                )
        except Exception as exc:  # Provider and interface errors are runtime dependent.
            self.last_error = str(exc)
            message = self._capture_error_message(exc)
            self._publish_event("error", message)
        finally:
            self.stop_event.set()
            try:
                self.stop_recording()
            except CaptureError:
                pass

    @staticmethod
    def _capture_error_message(exc: Exception) -> str:
        text = str(exc)
        lowered = text.lower()
        if any(token in lowered for token in ("permission", "access is denied", "winerror 5")):
            return (
                "Capture permission was denied. Check Npcap installation and interface "
                "permissions; Shaheen does not elevate itself."
            )
        if any(token in lowered for token in ("no such device", "interface", "adapter")):
            return f"Selected interface is unavailable or disconnected: {text}"
        if any(token in lowered for token in ("pcap", "wpcap", "npcap", "provider")):
            return (
                "Capture backend unavailable. Install Npcap with WinPcap API-compatible "
                f"mode and restart Shaheen. Details: {text}"
            )
        return f"Capture failed: {text}"

    def consumer(self) -> tuple[str, Any] | None:
        try:
            return self._control_events.get_nowait()
        except queue.Empty:
            pass
        try:
            item = self.packet_queue.get_nowait()
            if item[0] == "packet":
                with self._lock:
                    self._packets_delivered += 1
            return item
        except queue.Empty:
            return None

    def filtered_packets(self, packets: list[PacketRecord], expression: str) -> list[PacketRecord]:
        if not expression or not expression.strip():
            return packets
        return [packet for packet in packets if evaluate_filter(packet, expression)]
