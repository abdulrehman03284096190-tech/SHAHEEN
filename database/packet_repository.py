from __future__ import annotations

import json
import queue
import sqlite3
import threading
from dataclasses import replace
from collections.abc import Iterator
from datetime import datetime, timezone
from typing import Any, Callable

from analyzer.packet_parser import PacketRecord
from analyzer.filter_engine import compile_filter_sql
from database.connection import initialize_database


def packet_record_from_row(row: dict[str, Any]) -> PacketRecord:
    try:
        metadata = json.loads(row["metadata"] or "{}")
        details = json.loads(row["details"] or "{}")
    except (TypeError, json.JSONDecodeError) as exc:
        raise ValueError(f"Stored packet metadata is invalid: {exc}") from exc
    return PacketRecord(
        packet_number=row["packet_number"],
        timestamp=row["timestamp"],
        source_address=row["source_address"] or "",
        destination_address=row["destination_address"] or "",
        source_port=row["source_port"],
        destination_port=row["destination_port"],
        protocol=row["protocol"] or "UNKNOWN",
        packet_length=row["packet_length"] or 0,
        summary=row["summary"] or "",
        metadata={
            **metadata,
            "tcp_flags_syn": int(row.get("tcp_flags_syn", metadata.get("tcp_flags_syn", 0))),
        },
        details=details,
        session_id=row["capture_session_id"],
        record_id=row["id"],
    )


class PacketRepository:
    def __init__(self, connection: sqlite3.Connection) -> None:
        self.connection = connection

    def create_session(
        self,
        *,
        source_type: str,
        source_path: str,
        status: str,
    ) -> int:
        cursor = self.connection.execute(
            """
            INSERT INTO capture_sessions(
                source_type, source_path, start_timestamp, status
            ) VALUES (?, ?, ?, ?)
            """,
            (
                source_type,
                source_path,
                datetime.now(timezone.utc).isoformat(),
                status,
            ),
        )
        self.connection.commit()
        return int(cursor.lastrowid)

    def store_packets(
        self,
        session_id: int,
        packets: list[PacketRecord],
        *,
        source_path: str | None = None,
    ) -> list[int]:
        if not packets:
            return []
        record_ids = []
        with self.connection:
            for packet in packets:
                cursor = self.connection.execute(
                    """
                INSERT INTO packets(
                    capture_session_id, packet_number, timestamp, source_address,
                    destination_address, source_port, destination_port, protocol,
                    packet_length, summary, metadata, details, tcp_flags_syn,
                    original_reference
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                    (
                        session_id,
                        packet.packet_number,
                        packet.timestamp,
                        packet.source_address,
                        packet.destination_address,
                        packet.source_port,
                        packet.destination_port,
                        packet.protocol,
                        packet.packet_length,
                        packet.summary,
                        json.dumps(
                            packet.metadata,
                            ensure_ascii=False,
                            sort_keys=True,
                            default=str,
                        ),
                        json.dumps(
                            packet.details,
                            ensure_ascii=False,
                            sort_keys=True,
                            default=str,
                        ),
                        int(packet.metadata.get("tcp_flags_syn", 0)),
                        (
                            f"{source_path}#packet={packet.packet_number}"
                            if source_path
                            else f"session:{session_id}:packet:{packet.packet_number}"
                        ),
                    ),
                )
                record_id = int(cursor.lastrowid)
                packet.session_id = session_id
                packet.record_id = record_id
                record_ids.append(record_id)
            self.connection.execute(
                """
                UPDATE capture_sessions
                SET packet_count = packet_count + ?,
                    byte_count = byte_count + ?
                WHERE id = ?
                """,
                (len(packets), sum(packet.packet_length for packet in packets), session_id),
            )
        return record_ids

    def finish_session(
        self,
        session_id: int,
        status: str,
        *,
        capture_stats: dict[str, Any] | None = None,
    ) -> None:
        if status not in {"completed", "cancelled", "failed", "interrupted"}:
            raise ValueError(f"Unsupported capture-session status: {status}")
        self.connection.execute(
            """
            UPDATE capture_sessions
            SET status = ?, end_timestamp = ?, capture_stats = ?
            WHERE id = ?
            """,
            (
                status,
                datetime.now(timezone.utc).isoformat(),
                json.dumps(capture_stats or {}, sort_keys=True),
                session_id,
            ),
        )
        self.connection.commit()

    def get_session(self, session_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            "SELECT * FROM capture_sessions WHERE id = ?", (session_id,)
        ).fetchone()
        return dict(row) if row is not None else None

    def get_packet_page(
        self,
        session_id: int,
        *,
        limit: int = 200,
        offset: int = 0,
        expression: str = "",
    ) -> list[dict[str, Any]]:
        if limit < 1 or limit > 5000 or offset < 0:
            raise ValueError("limit must be 1..5000 and offset must be non-negative")
        filter_sql, filter_params = compile_filter_sql(expression)
        rows = self.connection.execute(
            """
            SELECT id, capture_session_id, packet_number, timestamp, source_address,
                   destination_address, source_port, destination_port, protocol,
                   packet_length, summary, metadata, details, tcp_flags_syn,
                   original_reference
            FROM packets
            WHERE capture_session_id = ? AND
            """
            + filter_sql
            + """
            ORDER BY timestamp, id
            LIMIT ? OFFSET ?
            """,
            (session_id, *filter_params, limit, offset),
        ).fetchall()
        return [dict(row) for row in rows]

    def count_packets(self, session_id: int, expression: str = "") -> int:
        filter_sql, filter_params = compile_filter_sql(expression)
        row = self.connection.execute(
            "SELECT COUNT(*) FROM packets WHERE capture_session_id = ? AND "
            + filter_sql,
            (session_id, *filter_params),
        ).fetchone()
        return int(row[0])

    def iter_packet_rows(
        self,
        session_id: int,
        *,
        batch_size: int = 500,
        expression: str = "",
    ) -> Iterator[dict[str, Any]]:
        if batch_size < 1:
            raise ValueError("batch_size must be greater than zero")
        filter_sql, filter_params = compile_filter_sql(expression)
        cursor = self.connection.execute(
            """
            SELECT id, capture_session_id, packet_number, timestamp, source_address,
                   destination_address, source_port, destination_port, protocol,
                   packet_length, summary, metadata, details, tcp_flags_syn,
                   original_reference
            FROM packets
            WHERE capture_session_id = ? AND
            """
            + filter_sql
            + """
            ORDER BY timestamp, id
            """,
            (session_id, *filter_params),
        )
        rows = cursor.fetchmany(batch_size)
        while rows:
            for row in rows:
                yield dict(row)
            rows = cursor.fetchmany(batch_size)

    def get_packet(self, record_id: int) -> dict[str, Any] | None:
        row = self.connection.execute(
            """
            SELECT id, capture_session_id, packet_number, timestamp, source_address,
                   destination_address, source_port, destination_port, protocol,
                   packet_length, summary, metadata, details, tcp_flags_syn,
                   original_reference
            FROM packets WHERE id = ?
            """,
            (record_id,),
        ).fetchone()
        return dict(row) if row is not None else None

    def recover_interrupted_sessions(self) -> int:
        cursor = self.connection.execute(
            """
            UPDATE capture_sessions
            SET status = 'interrupted', end_timestamp = ?
            WHERE status IN ('capturing', 'importing')
            """,
            (datetime.now(timezone.utc).isoformat(),),
        )
        self.connection.commit()
        return cursor.rowcount


class PacketStorageWorker:
    """Writes packet metadata in batches on its own SQLite connection."""

    def __init__(
        self,
        database_path: str,
        session_id: int,
        *,
        queue_limit: int = 5000,
        batch_size: int = 250,
        on_error: Callable[[Exception], None] | None = None,
    ) -> None:
        if queue_limit < 1 or batch_size < 1:
            raise ValueError("queue_limit and batch_size must be greater than zero")
        self.database_path = database_path
        self.session_id = session_id
        self.batch_size = batch_size
        self.queue: queue.Queue[PacketRecord | None] = queue.Queue(maxsize=queue_limit)
        self.on_error = on_error
        self.error: Exception | None = None
        self.dropped_packets = 0
        self._packets_persisted = 0
        self._state_lock = threading.Lock()
        self._stop_requested = threading.Event()
        self._thread = threading.Thread(
            target=self._run,
            name=f"shaheen-packet-store-{session_id}",
            daemon=True,
        )
        self._thread.start()

    @property
    def packets_persisted(self) -> int:
        with self._state_lock:
            return self._packets_persisted

    def _store_batch(
        self,
        repository: PacketRepository,
        packets: list[PacketRecord],
    ) -> None:
        if not packets:
            return
        repository.store_packets(self.session_id, packets)
        with self._state_lock:
            self._packets_persisted += len(packets)
        packets.clear()

    def submit(self, packet: PacketRecord) -> bool:
        with self._state_lock:
            if self._stop_requested.is_set() or self.error is not None:
                self.dropped_packets += 1
                return False
            try:
                self.queue.put_nowait(replace(packet, raw_bytes=b""))
                return True
            except queue.Full:
                self.dropped_packets += 1
                return False

    def stop(self, timeout: float = 10.0) -> None:
        self._stop_requested.set()
        if self.error is not None and not self._thread.is_alive():
            raise RuntimeError(
                f"Packet metadata storage failed: {self.error}"
            ) from self.error
        try:
            self.queue.put(None, timeout=timeout)
        except queue.Full as exc:
            raise TimeoutError("Packet storage queue did not drain before shutdown") from exc
        self._thread.join(timeout=timeout)
        if self._thread.is_alive():
            raise TimeoutError("Packet storage worker did not stop in time")
        if self.error is not None:
            raise RuntimeError(f"Packet metadata storage failed: {self.error}") from self.error

    def _run(self) -> None:
        connection: sqlite3.Connection | None = None
        batch: list[PacketRecord] = []
        try:
            connection = initialize_database(self.database_path)
            repository = PacketRepository(connection)
            while True:
                try:
                    item = self.queue.get(timeout=0.25)
                except queue.Empty:
                    if batch:
                        self._store_batch(repository, batch)
                    continue
                if item is None:
                    if batch:
                        self._store_batch(repository, batch)
                    break
                batch.append(item)
                if len(batch) >= self.batch_size:
                    self._store_batch(repository, batch)
            with self._state_lock:
                dropped_packets = self.dropped_packets
            if dropped_packets:
                connection.execute(
                    "UPDATE capture_sessions SET capture_stats = ? WHERE id = ?",
                    (
                        json.dumps(
                            {"metadata_queue_dropped": dropped_packets},
                            sort_keys=True,
                        ),
                        self.session_id,
                    ),
                )
                connection.commit()
        except Exception as exc:
            with self._state_lock:
                self.error = exc
                self.dropped_packets += len(batch)
                batch.clear()
                dropped_in_queue = 0
                while True:
                    try:
                        queued_packet = self.queue.get_nowait()
                    except queue.Empty:
                        break
                    if queued_packet is not None:
                        dropped_in_queue += 1
                self.dropped_packets += dropped_in_queue
            if self.on_error:
                self.on_error(exc)
        finally:
            if connection is not None:
                connection.close()
