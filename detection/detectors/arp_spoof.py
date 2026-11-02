from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from analyzer.packet_parser import PacketRecord


class ARPSpoofDetector:
    def __init__(self):
        self.ip_to_mac = {}
        self.history = []
    
    def detect(self, packets: Iterable[PacketRecord]) -> list[dict[str, object]]:
        alerts = []
        # Track IP->MAC mappings
        current_mappings = {}
        conflicts = []
        
        for pkt in packets:
            if pkt.protocol == "ARP" and pkt.details.get("arp"):
                arp = pkt.details["arp"]
                psrc = arp.get("psrc") or pkt.source_address
                # Try to get MAC from ethernet layer if available
                eth = pkt.details.get("ethernet", {})
                mac = eth.get("src")
                if psrc and mac:
                    if psrc in current_mappings and current_mappings[psrc] != mac:
                        # MAC changed - potential spoof
                        alerts.append({
                            "rule_id": "ARP_SPOOF",
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "severity": "high",
                            "title": "ARP spoofing suspected",
                            "description": f"IP {psrc} claimed by different MAC addresses ({current_mappings[psrc]} -> {mac}).",
                            "source_address": psrc,
                            "destination_address": arp.get("pdst", ""),
                            "confidence": 0.75,
                            "supporting_packets": [pkt.record_id] if pkt.record_id else [],
                            "evidence": {
                                "claimed_ip": psrc,
                                "previous_mac": current_mappings[psrc],
                                "new_mac": mac,
                            },
                            "recommendation": "Verify host identity. Check for MITM activity on local network segment.",
                        })
                    current_mappings[psrc] = mac
        
        return alerts
