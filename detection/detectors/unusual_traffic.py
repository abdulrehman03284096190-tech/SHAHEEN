from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from analyzer.packet_parser import PacketRecord


class UnusualTrafficDetector:
    def __init__(self):
        self.baseline = {}
    
    def detect(self, packets: Iterable[PacketRecord]) -> list[dict[str, object]]:
        alerts = []
        dst_port_counts = defaultdict(int)
        unusual_ports = [22, 23, 3389, 4444, 5555, 6666, 7777, 8888, 9999, 31337]
        packets_by_port = defaultdict(list)
        
        for pkt in packets:
            if pkt.destination_port in unusual_ports:
                packets_by_port[pkt.destination_port].append(pkt)
                if pkt.source_address and pkt.record_id:
                    dst_port_counts[(pkt.source_address, pkt.destination_port)] += 1
        
        for (src, port), count in dst_port_counts.items():
            if count >= 3:
                severity = "high" if port in [4444, 31337, 6666] else "medium"
                alerts.append({
                    "rule_id": "UNUSUAL_PORT",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": severity,
                    "title": "Connection to unusual/suspicious port",
                    "description": f"{src} connected to suspicious port {port} {count} times.",
                    "source_address": src,
                    "destination_address": "multiple",
                    "destination_port": port,
                    "confidence": 0.68,
                    "supporting_packets": [p.record_id for p in packets_by_port[port] if p.source_address == src and p.record_id][:50],
                    "evidence": {"port": port, "connection_count": count},
                    "recommendation": "Verify if connection to this port is authorized.",
                })
        
        return alerts
