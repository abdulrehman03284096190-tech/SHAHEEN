from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from typing import Iterable

from analyzer.packet_parser import PacketRecord


class PortScanDetector:
    def __init__(self, threshold_medium: int = 15, threshold_high: int = 30, window_seconds: int = 30):
        self.threshold_medium = threshold_medium
        self.threshold_high = threshold_high
        self.window_seconds = window_seconds

    def detect(self, packets: Iterable[PacketRecord]) -> list[dict[str, object]]:
        alerts = []
        # Track (src, dst) -> set of ports
        src_to_ports = defaultdict(set)
        src_to_packets = defaultdict(list)
        src_to_dests = defaultdict(set)
        
        for pkt in packets:
            if pkt.source_address and pkt.destination_port:
                src_to_ports[pkt.source_address].add(pkt.destination_port)
                if pkt.record_id:
                    src_to_packets[pkt.source_address].append(pkt.record_id)
                if pkt.destination_address:
                    src_to_dests[pkt.source_address].add(pkt.destination_address)
        
        for src, ports in src_to_ports.items():
            port_count = len(ports)
            if port_count >= self.threshold_medium:
                severity = "high" if port_count >= self.threshold_high or len(src_to_dests[src]) > 1 else "medium"
                alerts.append({
                    "rule_id": "PORT_SCAN",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": severity,
                    "title": "Potential port scanning",
                    "description": f"{src} contacted {port_count} distinct destination ports across {len(src_to_dests[src])} host(s).",
                    "source_address": src,
                    "destination_address": ", ".join(list(src_to_dests[src])[:5]) + ("..." if len(src_to_dests[src]) > 5 else "") or "multiple",
                    "confidence": 0.82,
                    "supporting_packets": src_to_packets[src][:100],
                    "evidence": {
                        "ports_scanned": sorted(list(ports))[:50],
                        "port_count": port_count,
                        "hosts_scanned": len(src_to_dests[src]),
                    },
                    "recommendation": "Investigate source host for reconnaissance activity. Check for other scan patterns.",
                })
        return alerts
