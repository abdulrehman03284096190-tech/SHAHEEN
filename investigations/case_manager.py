from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class TimelineEvent:
    event_id: int
    investigation_id: int
    timestamp: str | None
    event_type: str
    summary: str
    source_reference: str | None
    metadata: dict[str, Any]


class InvestigationManager:
    VALID_STATUSES = {"open", "in_progress", "closed"}

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def create_investigation(
        self,
        title: str,
        description: str = "",
        analyst_notes: str = "",
    ) -> int:
        if not title.strip():
            raise ValueError("Investigation title cannot be empty")
        with self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO investigations(title, description, status, analyst_notes)
                VALUES (?, ?, 'open', ?)
                """,
                (title.strip(), description, analyst_notes),
            )
            investigation_id = int(cursor.lastrowid)
            self.add_event(
                investigation_id,
                event_type="status",
                summary="Investigation created",
                metadata={"status": "open"},
            )
        return investigation_id

    def add_event(
        self,
        investigation_id: int,
        *,
        event_type: str,
        summary: str,
        timestamp: str | None = None,
        source_reference: str | None = None,
        metadata: dict[str, Any] | None = None,
    ) -> int:
        if not event_type.strip() or not summary.strip():
            raise ValueError("Event type and summary are required")
        event_timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        with self.connection:
            cursor = self.connection.execute(
                """
                INSERT INTO investigation_events(
                    investigation_id, timestamp, event_type, summary, source_reference, metadata
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    investigation_id,
                    event_timestamp,
                    event_type.strip(),
                    summary.strip(),
                    source_reference,
                    json.dumps(metadata or {}, ensure_ascii=False, sort_keys=True),
                ),
            )
            self.connection.execute(
                "UPDATE investigations SET updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (investigation_id,),
            )
        return int(cursor.lastrowid)

    def add_packet_event(self, investigation_id: int, packet: Any) -> int:
        return self.add_event(
            investigation_id,
            event_type="packet",
            timestamp=packet.timestamp,
            summary=f"{packet.protocol}: {packet.summary}",
            source_reference=f"packet:{packet.packet_number}",
            metadata={
                "packet_number": packet.packet_number,
                "source": packet.source_address,
                "destination": packet.destination_address,
                "length": packet.packet_length,
                "protocol": packet.protocol,
            },
        )

    def add_alert_event(self, investigation_id: int, alert: dict[str, Any]) -> int:
        return self.add_event(
            investigation_id,
            event_type="alert",
            timestamp=alert.get("timestamp"),
            summary=str(alert.get("title", "Detection alert")),
            source_reference=(
                f"alert:{alert['id']}" if alert.get("id") is not None else None
            ),
            metadata=alert,
        )

    def add_note(self, investigation_id: int, note: str) -> int:
        return self.add_event(investigation_id, event_type="note", summary=note)

    def set_status(self, investigation_id: int, status: str) -> None:
        if status not in self.VALID_STATUSES:
            raise ValueError(f"Unsupported investigation status: {status}")
        with self.connection:
            cursor = self.connection.execute(
                "UPDATE investigations SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (status, investigation_id),
            )
            if cursor.rowcount == 0:
                raise ValueError(f"Investigation {investigation_id} does not exist")
            self.add_event(
                investigation_id,
                event_type="status",
                summary=f"Investigation status changed to {status}",
                metadata={"status": status},
            )

    def get_investigation(self, investigation_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM investigations WHERE id = ?", (investigation_id,)
        ).fetchone()
        return dict(row) if row is not None else None

    def list_investigations(self) -> list[dict[str, Any]]:
        rows = self.connection.execute(
            "SELECT * FROM investigations ORDER BY updated_at DESC, id DESC"
        ).fetchall()
        return [dict(row) for row in rows]

    def get_timeline(
        self,
        investigation_id: int,
        *,
        event_type: str | None = None,
    ) -> list[TimelineEvent]:
        if event_type:
            rows = self.connection.execute(
                """
                SELECT * FROM investigation_events
                WHERE investigation_id = ? AND event_type = ?
                """,
                (investigation_id, event_type),
            ).fetchall()
        else:
            rows = self.connection.execute(
                "SELECT * FROM investigation_events WHERE investigation_id = ?",
                (investigation_id,),
            ).fetchall()

        events: list[TimelineEvent] = []
        for row in rows:
            try:
                metadata = json.loads(row["metadata"] or "{}")
            except json.JSONDecodeError:
                metadata = {"unparsed_metadata": row["metadata"]}
            events.append(
                TimelineEvent(
                    event_id=row["id"],
                    investigation_id=row["investigation_id"],
                    timestamp=row["timestamp"],
                    event_type=row["event_type"],
                    summary=row["summary"],
                    source_reference=row["source_reference"],
                    metadata=metadata,
                )
            )
        return sorted(events, key=_timeline_sort_key)


def _timeline_sort_key(event: TimelineEvent) -> tuple[int, datetime, int]:
    if not event.timestamp:
        return (1, datetime.max.replace(tzinfo=timezone.utc), event.event_id)
    try:
        parsed = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return (0, parsed.astimezone(timezone.utc), event.event_id)
    except ValueError:
        return (1, datetime.max.replace(tzinfo=timezone.utc), event.event_id)
