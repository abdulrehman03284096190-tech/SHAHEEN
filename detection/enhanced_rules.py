from __future__ import annotations

from dataclasses import dataclass


@dataclass
class DetectionRule:
    rule_id: str
    name: str
    description: str
    severity: str = "medium"
    enabled: bool = True
    config: dict[str, object] | None = None


ENHANCED_RULES = [
    DetectionRule("PORT_SCAN", "Potential port scanning", "Source host attempts many unique destination ports.", "high", True, {"threshold_medium": 15, "threshold_high": 30, "window_seconds": 30}),
    DetectionRule("ARP_SPOOF", "ARP spoofing suspected", "IP-MAC mapping conflict detected.", "high", True, {}),
    DetectionRule("DNS_ANOMALY", "Suspicious DNS activity", "Excessive or anomalous DNS queries.", "medium", True, {"threshold": 20}),
    DetectionRule("DNS_LONG_DOMAIN", "Unusually long DNS domain", "Long domain possibly indicating tunneling.", "medium", True, {"length_threshold": 30}),
    DetectionRule("SYN_FLOOD", "Potential SYN flood attack", "Excessive SYN packets with few responses.", "critical", True, {"threshold": 100}),
    DetectionRule("SUSPICIOUS_IP", "Watchlisted IP detected", "Traffic involving watchlisted IP.", "high", True, {}),
    DetectionRule("UNUSUAL_PORT", "Connection to unusual/suspicious port", "Traffic to commonly exploited ports.", "medium", True, {}),
    DetectionRule("CONNECTION_RETRY", "Repeated connection attempts", "Many failed TCP connections in a short time window.", "high", True, {"threshold": 10}),
    DetectionRule("TRAFFIC_SPIKE", "Traffic spike detected", "Unusual increase in traffic volume.", "medium", True, {"threshold": 50}),
]
