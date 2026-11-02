from __future__ import annotations

import os
from pathlib import Path


def get_or_prompt_secret(name: str) -> str | None:
    value = os.getenv(name)
    if value:
        return value
    return None


def ensure_secret_file(path: str) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    if not p.exists():
        p.write_text("", encoding="utf-8")
    return p
