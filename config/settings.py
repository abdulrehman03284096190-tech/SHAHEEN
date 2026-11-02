from __future__ import annotations

import os
import sys
from dataclasses import dataclass
import json
import logging
from pathlib import Path
import sqlite3

from dotenv import load_dotenv

from config.defaults import (
    DEFAULT_AI_MODEL,
    DEFAULT_AI_PROVIDER,
    DEFAULT_CAPTURE_PATH,
    DEFAULT_DATABASE_PATH,
    DEFAULT_FILTER,
    DEFAULT_LOG_PATH,
    DEFAULT_REPORT_PATH,
    DEFAULT_SNAP_LENGTH,
    DEFAULT_THEME,
)

logger = logging.getLogger(__name__)
EDITABLE_SETTINGS = ("theme", "capture_filter", "report_path")


@dataclass
class AppSettings:
    app_name: str = "Shaheen"
    theme: str = DEFAULT_THEME
    database_path: str = DEFAULT_DATABASE_PATH
    capture_path: str = DEFAULT_CAPTURE_PATH
    report_path: str = DEFAULT_REPORT_PATH
    log_path: str = DEFAULT_LOG_PATH
    ai_provider: str = DEFAULT_AI_PROVIDER
    ai_model: str = DEFAULT_AI_MODEL
    capture_filter: str = DEFAULT_FILTER
    snap_length: int = DEFAULT_SNAP_LENGTH
    enable_ai: bool = False


def validate_editable_settings(
    *,
    theme: str,
    capture_filter: str,
    report_path: str,
) -> dict[str, str]:
    if theme not in {"dark", "light", "system"}:
        raise ValueError("Theme must be dark, light, or system.")
    if (
        not isinstance(capture_filter, str)
        or len(capture_filter) > 2048
        or any(character in capture_filter for character in "\x00\r\n")
    ):
        raise ValueError("Capture filter must be a single line of at most 2048 characters.")
    if not isinstance(report_path, str) or not report_path.strip():
        raise ValueError("Report directory must be a non-empty path.")
    target = Path(report_path.strip()).expanduser()
    if not target.is_absolute():
        target = Path.home() / target
    return {
        "theme": theme,
        "capture_filter": capture_filter.strip(),
        "report_path": str(target),
    }


def load_persisted_settings(
    settings: AppSettings,
    connection: sqlite3.Connection,
) -> AppSettings:
    rows = connection.execute(
        "SELECT key, value FROM app_settings WHERE key IN (?, ?, ?)",
        EDITABLE_SETTINGS,
    ).fetchall()
    current = {
        "theme": settings.theme,
        "capture_filter": settings.capture_filter,
        "report_path": settings.report_path,
    }
    for row in rows:
        key = row["key"]
        try:
            current[key] = json.loads(row["value"])
            validated = validate_editable_settings(**current)
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            logger.warning("Ignoring invalid persisted setting %s: %s", key, exc)
            current[key] = getattr(settings, key)
            continue
        for field in EDITABLE_SETTINGS:
            setattr(settings, field, validated[field])
    return settings


def save_persisted_settings(
    settings: AppSettings,
    connection: sqlite3.Connection,
) -> None:
    validated = validate_editable_settings(
        theme=settings.theme,
        capture_filter=settings.capture_filter,
        report_path=settings.report_path,
    )
    Path(validated["report_path"]).mkdir(parents=True, exist_ok=True)
    with connection:
        connection.executemany(
            """INSERT INTO app_settings(key, value, updated_at)
               VALUES (?, ?, CURRENT_TIMESTAMP)
               ON CONFLICT(key) DO UPDATE SET
                   value = excluded.value, updated_at = excluded.updated_at""",
            [(key, json.dumps(value)) for key, value in validated.items()],
        )
    for field in EDITABLE_SETTINGS:
        setattr(settings, field, validated[field])


def load_settings() -> AppSettings:
    load_dotenv()
    frozen = getattr(sys, "frozen", False)
    if frozen:
        local_app_data = os.getenv("LOCALAPPDATA") or os.getenv("APPDATA")
        base = (
            Path(local_app_data) / "Shaheen"
            if local_app_data
            else Path.home() / "AppData" / "Local" / "Shaheen"
        )
    else:
        base = Path(__file__).resolve().parents[1]
    settings = AppSettings(
        app_name=os.getenv("APP_NAME", "Shaheen"),
        theme=os.getenv("APP_THEME", DEFAULT_THEME),
        database_path=os.getenv(
            "DATABASE_PATH",
            str(base / "data" / "shaheen.db")
            if frozen
            else str(base / DEFAULT_DATABASE_PATH),
        ),
        capture_path=os.getenv(
            "CAPTURE_PATH",
            str(base / "captures") if frozen else str(base / DEFAULT_CAPTURE_PATH),
        ),
        report_path=os.getenv(
            "REPORT_PATH",
            str(base / "reports_output") if frozen else str(base / DEFAULT_REPORT_PATH),
        ),
        log_path=os.getenv(
            "LOG_PATH",
            str(base / "logs" / "shaheen.log") if frozen else str(base / DEFAULT_LOG_PATH),
        ),
        ai_provider=os.getenv("AI_PROVIDER", DEFAULT_AI_PROVIDER),
        ai_model=os.getenv("AI_MODEL", DEFAULT_AI_MODEL),
        capture_filter=os.getenv("CAPTURE_FILTER", DEFAULT_FILTER),
        snap_length=int(os.getenv("SNAP_LENGTH", DEFAULT_SNAP_LENGTH)),
        enable_ai=os.getenv("ENABLE_AI", "false").lower() in {"1", "true", "yes"},
    )
    validate_editable_settings(
        theme=settings.theme,
        capture_filter=settings.capture_filter,
        report_path=settings.report_path,
    )
    Path(settings.database_path).parent.mkdir(parents=True, exist_ok=True)
    Path(settings.capture_path).mkdir(parents=True, exist_ok=True)
    Path(settings.report_path).mkdir(parents=True, exist_ok=True)
    Path(settings.log_path).parent.mkdir(parents=True, exist_ok=True)
    return settings
