from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timezone
from typing import Iterable

from analyzer.packet_parser import PacketRecord
from detection.rules import DEFAULT_RULES


class DetectionEngine:
    def __init__(self) -> None:
        self.rules = DEFAULT_RULES

    @staticmethod
    def _dedupe(alerts: list[dict[str, object]]) -> list[dict[str, object]]:
        seen: set[tuple[str, str, str]] = set()
        deduped: list[dict[str, object]] = []
        for alert in alerts:
            key = (
                str(alert.get("rule_id", "")),
                str(alert.get("source_address", "")),
                str(alert.get("destination_address", "")),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(alert)
        return deduped

    def generate_alerts(self, packets: Iterable[PacketRecord]) -> list[dict[str, object]]:
        alerts: list[dict[str, object]] = []
        by_source: dict[str, set[str]] = defaultdict(set)
        by_dns: dict[str, int] = defaultdict(int)
        retries: dict[str, int] = defaultdict(int)
        by_dest: dict[str, int] = defaultdict(int)
        packet_ids: dict[str, list[int]] = defaultdict(list)

        for packet in packets:
            if packet.source_address:
                by_source[packet.source_address].add(str(packet.destination_port or ""))
            if packet.source_address and packet.destination_address:
                by_dest[packet.source_address] += 1
            if packet.source_address and packet.record_id is not None:
                packet_ids[packet.source_address].append(packet.record_id)
            if packet.protocol.upper() == "DNS":
                by_dns[packet.source_address] += 1
            if packet.protocol.upper() == "TCP":
                retries[packet.source_address] += 1

        for source, ports in by_source.items():
            if len(ports) >= 15:
                alerts.append({
                    "rule_id": "PORT_SCAN",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "high",
                    "title": "Potential port scanning",
                    "description": f"{source} contacted {len(ports)} distinct ports within the observed capture.",
                    "source_address": source,
                    "destination_address": "multiple",
                    "confidence": 0.82,
                    "supporting_packets": packet_ids[source][:100],
                })

        for source, count in by_dns.items():
            if count >= 20:
                alerts.append({
                    "rule_id": "DNS_ANOMALY",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "medium",
                    "title": "Suspicious DNS activity",
                    "description": f"{source} generated {count} DNS queries.",
                    "source_address": source,
                    "destination_address": "resolver",
                    "confidence": 0.65,
                    "supporting_packets": packet_ids[source][:100],
                })

        for source, count in retries.items():
            if count >= 10:
                alerts.append({
                    "rule_id": "CONNECTION_RETRY",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "high",
                    "title": "Repeated connection attempts",
                    "description": f"{source} initiated {count} TCP-related connection attempts without corroborating handshake evidence.",
                    "source_address": source,
                    "destination_address": "multiple",
                    "confidence": 0.7,
                    "supporting_packets": packet_ids[source][:100],
                })

        for source, count in by_dest.items():
            if count >= 50:
                alerts.append({
                    "rule_id": "TRAFFIC_SPIKE",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "severity": "medium",
                    "title": "Traffic spike detected",
                    "description": f"{source} produced {count} observed packets in a short interval.",
                    "source_address": source,
                    "destination_address": "multiple",
                    "confidence": 0.6,
                    "supporting_packets": packet_ids[source][:100],
                })

        return self._dedupe(alerts)
