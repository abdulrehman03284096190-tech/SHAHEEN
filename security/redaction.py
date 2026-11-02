from __future__ import annotations


def redact_sensitive(text: str) -> str:
    replaced = text.replace("api_key", "[REDACTED]")
    replaced = replaced.replace("sk-", "[REDACTED]")
    return replaced
