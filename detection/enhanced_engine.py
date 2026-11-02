from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from analyzer.packet_parser import PacketRecord
from detection.detectors.detector_manager import DetectorManager


class EnhancedDetectionEngine:
    def __init__(self, watchlist=None):
        self.manager = DetectorManager(watchlist=watchlist)
    
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
    
    def generate_alerts(self, packets: Iterable[PacketRecord], include_evidence=True) -> list[dict[str, object]]:
        alerts = self.manager.run_all(packets)
        # Ensure all required fields
        for alert in alerts:
            if "alert_id" not in alert:
                alert["alert_id"] = f"ALERT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f')}"
            if "status" not in alert:
                alert["status"] = "new"
            if "detection_module" not in alert:
                alert["detection_module"] = alert.get("rule_id", "UNKNOWN")
        return self._dedupe(alerts)
