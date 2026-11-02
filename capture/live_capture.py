from __future__ import annotations

import threading
from queue import Queue
from typing import Any

from scapy.all import sniff

from analyzer.packet_parser import parse_packet


class LiveCaptureWorker:
    def __init__(self, iface: str, packet_queue: Queue, stop_event: threading.Event, filter_expr: str | None = None) -> None:
        self.iface = iface
        self.packet_queue = packet_queue
        self.stop_event = stop_event
        self.filter_expr = filter_expr
        self.thread: threading.Thread | None = None

    def run(self) -> None:
        def _callback(packet: Any) -> None:
            if self.stop_event.is_set():
                raise KeyboardInterrupt
            self.packet_queue.put(parse_packet(packet, self.packet_queue.qsize() + 1))

        self.thread = threading.Thread(target=lambda: sniff(iface=self.iface, prn=_callback, stop_filter=lambda _: self.stop_event.is_set(), store=False), daemon=True)
        self.thread.start()

    def stop(self) -> None:
        self.stop_event.set()
