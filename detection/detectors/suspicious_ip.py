from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable, Set

from analyzer.packet_parser import PacketRecord


class SuspiciousIPMonitor:
    def __init__(self, watchlist: Set[str] | None = None):
        self.watchlist = watchlist or set()
    
    def detect(self, packets: Iterable[PacketRecord]) -> list[dict[str, object]]:
        alerts = []
        watchlist_hits = defaultdict(list)
        
        for pkt in packets:
            if pkt.source_address in self.watchlist:
                watchlist_hits[pkt.source_address].append(pkt.record_id)
            if pkt.destination_address in self.watchlist:
                watchlist_hits[pkt.destination_address].append(pkt.record_id)
        
        for ip, packet_ids in watchlist_hits.items():
            if packet_ids:
                alerts.append({
                    "rule_id": "SUSPICIOUS_IP",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "high",
                    "title": "Watchlisted IP detected",
                    "description": f"Traffic involving watchlisted IP {ip} observed ({len(packet_ids)} packets).",
                    "source_address": ip,
                    "destination_address": "multiple",
                    "confidence": 0.70,
                    "supporting_packets": packet_ids[:100],
                    "evidence": {"watchlisted_ip": ip, "packet_count": len(packet_ids)},
                    "recommendation": "Review traffic with this watchlisted IP for malicious activity.",
                })
        
        return alerts
