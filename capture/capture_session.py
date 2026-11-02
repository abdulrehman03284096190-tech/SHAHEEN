from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class CaptureSession:
    id: int | None = None
    source_type: str = "pcap"
    source_path: str = ""
    start_timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    end_timestamp: str | None = None
    status: str = "initialized"
    packet_count: int = 0
    byte_count: int = 0
    capture_stats: dict[str, object] = field(default_factory=dict)

    def to_record(self) -> dict[str, object]:
        return {
            "id": self.id,
            "source_type": self.source_type,
            "source_path": self.source_path,
            "start_timestamp": self.start_timestamp,
            "end_timestamp": self.end_timestamp,
            "status": self.status,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "capture_stats": str(self.capture_stats),
        }
