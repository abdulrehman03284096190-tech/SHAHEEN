from __future__ import annotations

import json
import sqlite3
from datetime import date
from typing import Any


class AlertRepository:
    STATUSES = {"new", "acknowledged", "resolved"}

    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def persist_generated(
        self,
        session_id: int,
        alerts: list[dict[str, Any]],
    ) -> list[int]:
        inserted: list[int] = []
        with self.connection:
            for alert in alerts:
                rule_id = str(alert["rule_id"])
                source = str(alert.get("source_address", ""))
                destination = str(alert.get("destination_address", ""))
                existing = self.connection.execute(
                    """SELECT id FROM alerts
                       WHERE capture_session_id = ? AND rule_id = ?
                         AND source_address = ? AND destination_address = ?
                       LIMIT 1""",
                    (session_id, rule_id, source, destination),
                ).fetchone()
                if existing:
                    continue
                references = alert.get("supporting_packets", [])
                if not isinstance(references, list):
                    raise ValueError("Alert evidence references must be a list.")
                if any(
                    isinstance(reference, bool)
                    or not isinstance(reference, int)
                    or reference < 1
                    for reference in references
                ):
                    raise ValueError("Alert evidence references must be positive packet IDs.")
                packet_ids = references
                cursor = self.connection.execute(
                    """INSERT INTO alerts(
                           capture_session_id, rule_id, timestamp, severity, title,
                           description, source_address, destination_address,
                           supporting_packets, status, confidence
                       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'new', ?)""",
                    (
                        session_id,
                        rule_id,
                        str(alert["timestamp"]),
                        str(alert["severity"]),
                        str(alert["title"]),
                        str(alert["description"]),
                        source,
                        destination,
                        json.dumps(packet_ids),
                        float(alert.get("confidence", 0.0)),
                    ),
                )
                inserted.append(int(cursor.lastrowid))
        return inserted

    def list_alerts(
        self,
        *,
        severity: str = "All",
        status: str = "All",
        source: str = "",
        destination: str = "",
        start_date: str = "",
        end_date: str = "",
        limit: int = 1000,
    ) -> list[sqlite3.Row]:
        if isinstance(limit, bool):
            raise ValueError("Alert query limit must be a positive integer.")
        clauses: list[str] = []
        parameters: list[Any] = []
        if severity and severity != "All":
            clauses.append("severity = ?")
            parameters.append(severity)
        if status and status != "All":
            clauses.append("status = ?")
            parameters.append(status)
        if source.strip():
            clauses.append("source_address LIKE ?")
            parameters.append(f"%{source.strip()}%")
        if destination.strip():
            clauses.append("destination_address LIKE ?")
            parameters.append(f"%{destination.strip()}%")
        if start_date:
            date.fromisoformat(start_date)
            clauses.append("date(timestamp) >= ?")
            parameters.append(start_date)
        if end_date:
            date.fromisoformat(end_date)
            clauses.append("date(timestamp) <= ?")
            parameters.append(end_date)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        parameters.append(max(1, min(int(limit), 10000)))
        return self.connection.execute(
            f"SELECT * FROM alerts {where} ORDER BY timestamp DESC, id DESC LIMIT ?",
            parameters,
        ).fetchall()

    def update_status(
        self,
        alert_id: int,
        status: str,
        analyst_notes: str | None = None,
    ) -> bool:
        if status not in self.STATUSES:
            raise ValueError(f"Unsupported alert status: {status}")
        if analyst_notes is None:
            cursor = self.connection.execute(
                "UPDATE alerts SET status = ? WHERE id = ?",
                (status, int(alert_id)),
            )
        else:
            cursor = self.connection.execute(
                "UPDATE alerts SET status = ?, analyst_notes = ? WHERE id = ?",
                (status, analyst_notes.strip(), int(alert_id)),
            )
        self.connection.commit()
        return cursor.rowcount > 0
