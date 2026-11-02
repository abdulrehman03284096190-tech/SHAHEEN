from database.connection import initialize_database


def test_database_initializes_schema(tmp_path) -> None:
    db_path = tmp_path / "shaheen.db"
    conn = initialize_database(str(db_path))
    count = conn.execute("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='capture_sessions'").fetchone()[0]
    assert count == 1
    conn.close()
