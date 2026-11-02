from __future__ import annotations

import csv
import json
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Any, Iterable


class CSVExporter:
    @staticmethod
    def _row_mapping(row: Any) -> dict[str, Any]:
        if is_dataclass(row):
            return asdict(row)
        if isinstance(row, dict):
            return row
        if hasattr(row, "keys"):
            return dict(row)
        raise TypeError(f"CSV rows must be mappings or dataclass instances, got {type(row).__name__}")

    @staticmethod
    def _cell_value(value: Any) -> str | int | float | None:
        if value is None or isinstance(value, (str, int, float)):
            text = value
        else:
            text = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
        if isinstance(text, str) and text.lstrip().startswith(("=", "+", "-", "@")):
            return "'" + text
        return text

    @classmethod
    def export_rows(
        cls,
        path: str,
        rows: Iterable[Any],
        *,
        fieldnames: list[str] | None = None,
    ) -> str:
        if fieldnames is None:
            normalized = [cls._row_mapping(row) for row in rows]
            columns = list(dict.fromkeys(key for row in normalized for key in row))
            rows_to_write: Iterable[Any] = normalized
        else:
            columns = fieldnames
            rows_to_write = rows
        if not columns:
            raise ValueError("CSV export requires field names or at least one row")

        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        with output.open("w", newline="", encoding="utf-8-sig") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            for raw_row in rows_to_write:
                row = cls._row_mapping(raw_row)
                writer.writerow({key: cls._cell_value(row.get(key)) for key in columns})
        return str(output)

    @classmethod
    def export_packets(cls, path: str, packets: Iterable[Any]) -> str:
        fields = [
            "packet_number",
            "timestamp",
            "source_address",
            "destination_address",
            "source_port",
            "destination_port",
            "protocol",
            "packet_length",
            "summary",
        ]
        return cls.export_rows(path, packets, fieldnames=fields)

    @classmethod
    def export_alerts(cls, path: str, alerts: Iterable[Any]) -> str:
        fields = [
            "id",
            "rule_id",
            "timestamp",
            "severity",
            "title",
            "description",
            "source_address",
            "destination_address",
            "supporting_packets",
            "confidence",
            "status",
        ]
        return cls.export_rows(path, alerts, fieldnames=fields)

    @classmethod
    def export_timeline(cls, path: str, events: Iterable[Any]) -> str:
        fields = [
            "event_id",
            "investigation_id",
            "timestamp",
            "event_type",
            "summary",
            "source_reference",
            "metadata",
        ]
        return cls.export_rows(path, events, fieldnames=fields)
