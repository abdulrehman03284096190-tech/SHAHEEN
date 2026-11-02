from __future__ import annotations

import logging
from pathlib import Path

from config.logging_config import configure_logging
from config.settings import AppSettings, load_persisted_settings, load_settings
from core.event_bus import EventBus
from database.connection import initialize_database
from database.packet_repository import PacketRepository


class ShaheenApplication:
    def __init__(self, settings: AppSettings | None = None) -> None:
        self.settings = settings or load_settings()
        self.logger = configure_logging(self.settings.log_path)
        self.bus = EventBus()
        self.db = initialize_database(self.settings.database_path)
        load_persisted_settings(self.settings, self.db)
        recovered = PacketRepository(self.db).recover_interrupted_sessions()
        if recovered:
            self.logger.warning("Marked %s unfinished capture session(s) as interrupted", recovered)
        self.logger.info("Shaheen application initialized")

    def bootstrap(self) -> None:
        Path(self.settings.capture_path).mkdir(parents=True, exist_ok=True)
        Path(self.settings.report_path).mkdir(parents=True, exist_ok=True)
        self.logger.info("Bootstrap complete")
