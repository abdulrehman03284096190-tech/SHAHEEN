from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from analyzer.packet_parser import PacketRecord


class SYNFloodDetector:
    def __init__(self, threshold: int = 100, window_seconds: int = 10):
        self.threshold = threshold
        self.window_seconds = window_seconds
    
    def detect(self, packets: Iterable[PacketRecord]) -> list[dict[str, object]]:
        alerts = []
        syn_counts = defaultdict(int)
        syn_packets = defaultdict(list)
        syn_ack_counts = defaultdict(int)
        
        for pkt in packets:
            if pkt.protocol == "TCP":
                tcp_flags = pkt.metadata.get("tcp_flags", {})
                if tcp_flags.get("syn") and not tcp_flags.get("ack"):
                    syn_counts[pkt.destination_address] += 1
                    if pkt.record_id:
                        syn_packets[pkt.destination_address].append(pkt.record_id)
                elif tcp_flags.get("syn") and tcp_flags.get("ack"):
                    syn_ack_counts[pkt.source_address] += 1
        
        for dst, count in syn_counts.items():
            if count >= self.threshold:
                ratio = syn_ack_counts.get(dst, 0) / count if count > 0 else 0
                severity = "critical" if count >= self.threshold * 2 or ratio < 0.1 else "high"
                alerts.append({
                    "rule_id": "SYN_FLOOD",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": severity,
                    "title": "Potential SYN flood attack",
                    "description": f"{count} SYN packets to {dst} with only {syn_ack_counts.get(dst, 0)} SYN-ACK responses (ratio: {ratio:.2f}).",
                    "source_address": "multiple",
                    "destination_address": dst,
                    "confidence": 0.85,
                    "supporting_packets": syn_packets[dst][:100],
                    "evidence": {
                        "syn_count": count,
                        "syn_ack_count": syn_ack_counts.get(dst, 0),
                        "ratio": ratio,
                    },
                    "recommendation": "Investigate for DDoS SYN flood. Consider rate limiting and SYN cookies.",
                })
        
        return alerts
