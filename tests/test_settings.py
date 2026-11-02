import json

import pytest

from config.settings import (
    AppSettings,
    load_persisted_settings,
    save_persisted_settings,
    validate_editable_settings,
)
from database.connection import initialize_database


def test_editable_settings_persist_across_application_restarts(tmp_path):
    path = tmp_path / "shaheen.db"
    connection = initialize_database(str(path))
    configured = AppSettings(
        database_path=str(path),
        report_path=str(tmp_path / "reports"),
        theme="light",
        capture_filter="tcp port 443",
    )

    save_persisted_settings(configured, connection)
    connection.close()

    reopened = initialize_database(str(path))
    restored = AppSettings(database_path=str(path))
    load_persisted_settings(restored, reopened)

    assert restored.theme == "light"
    assert restored.capture_filter == "tcp port 443"
    assert restored.report_path == str(tmp_path / "reports")
    assert (tmp_path / "reports").is_dir()
    reopened.close()


def test_invalid_persisted_setting_is_ignored_without_discarding_valid_values(
    tmp_path,
    caplog,
):
    connection = initialize_database(str(tmp_path / "shaheen.db"))
    with connection:
        connection.executemany(
            "INSERT INTO app_settings(key, value) VALUES (?, ?)",
            [
                ("theme", json.dumps("light")),
                ("capture_filter", json.dumps("tcp\nmalformed")),
            ],
        )
    settings = AppSettings(report_path=str(tmp_path / "reports"))

    load_persisted_settings(settings, connection)

    assert settings.theme == "light"
    assert settings.capture_filter == ""
    assert "Ignoring invalid persisted setting capture_filter" in caplog.text
    connection.close()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("theme", "neon"),
        ("capture_filter", "tcp\nudp"),
        ("report_path", " "),
    ],
)
def test_editable_settings_validation(field, value):
    settings = {
        "theme": "dark",
        "capture_filter": "tcp",
        "report_path": "reports",
    }
    settings[field] = value
    with pytest.raises(ValueError):
        validate_editable_settings(**settings)
