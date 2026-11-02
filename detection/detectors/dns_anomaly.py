from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from analyzer.packet_parser import PacketRecord


class DNSAnomalyDetector:
    def __init__(self, threshold: int = 20, long_domain_threshold: int = 30):
        self.threshold = threshold
        self.long_domain_threshold = long_domain_threshold
    
    def detect(self, packets: Iterable[PacketRecord]) -> list[dict[str, object]]:
        alerts = []
        dns_counts = defaultdict(int)
        dns_packets = defaultdict(list)
        long_domains = []
        
        for pkt in packets:
            if pkt.protocol == "DNS":
                dns_counts[pkt.source_address] += 1
                if pkt.record_id:
                    dns_packets[pkt.source_address].append(pkt.record_id)
                dns_info = pkt.details.get("dns", {})
                qname = dns_info.get("qdname", "")
                if len(qname) > self.long_domain_threshold:
                    long_domains.append((pkt.source_address, qname, pkt.record_id))
        
        for src, count in dns_counts.items():
            if count >= self.threshold:
                alerts.append({
                    "rule_id": "DNS_ANOMALY",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "medium",
                    "title": "Suspicious DNS activity",
                    "description": f"{src} generated {count} DNS queries.",
                    "source_address": src,
                    "destination_address": "resolver",
                    "confidence": 0.65,
                    "supporting_packets": dns_packets[src][:100],
                    "evidence": {"query_count": count},
                    "recommendation": "Review DNS queries for tunneling or data exfiltration indicators.",
                })
        
        for src, domain, pkt_id in long_domains[:10]:
            alerts.append({
                "rule_id": "DNS_LONG_DOMAIN",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "severity": "medium",
                "title": "Unusually long DNS domain",
                "description": f"Long domain name queried: {domain[:60]}...",
                "source_address": src,
                "destination_address": "resolver",
                "confidence": 0.60,
                "supporting_packets": [pkt_id] if pkt_id else [],
                "evidence": {"domain": domain, "length": len(domain)},
                "recommendation": "Check if domain is legitimate or indicates DNS tunneling.",
            })
        
        return alerts
