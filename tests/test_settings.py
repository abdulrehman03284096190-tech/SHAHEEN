import json

import pytest

import config.settings as settings_module
from config.settings import (
    AppSettings,
    load_persisted_settings,
    load_settings,
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


def test_frozen_settings_use_per_user_app_data_and_config_file(tmp_path, monkeypatch):
    app_data = tmp_path / "Shaheen"
    loaded_dotenv_paths = []
    monkeypatch.setattr(settings_module.sys, "frozen", True, raising=False)
    monkeypatch.setattr(
        settings_module,
        "load_dotenv",
        lambda path=None: loaded_dotenv_paths.append(path),
    )
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    for variable in ("DATABASE_PATH", "CAPTURE_PATH", "REPORT_PATH", "LOG_PATH"):
        monkeypatch.delenv(variable, raising=False)

    settings = load_settings()

    assert settings.database_path == str(app_data / "data" / "shaheen.db")
    assert settings.capture_path == str(app_data / "captures")
    assert settings.report_path == str(app_data / "reports_output")
    assert settings.log_path == str(app_data / "logs" / "shaheen.log")
    assert loaded_dotenv_paths == [app_data / "config" / ".env"]
    assert all(
        (app_data / directory).is_dir()
        for directory in ("config", "captures", "reports_output", "logs", "data", "backups")
    )
