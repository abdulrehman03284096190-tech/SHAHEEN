from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class AIRequest:
    prompt: str
    evidence: list[str] | None = None


class AIProvider:
    def __init__(self, provider: str = "mock", api_key: str | None = None) -> None:
        self.provider = provider
        self.api_key = api_key

    def analyze(self, request: AIRequest) -> dict[str, Any]:
        if self.provider.lower() == "mock":
            return {
                "summary": "Mock AI analysis: evidence reviewed; no external service used.",
                "observed_facts": request.evidence or ["No specific evidence supplied."],
                "potential_explanations": ["Traffic pattern is consistent with standard host activity."],
                "confidence": 0.5,
                "limitations": ["This response is generated from a mock provider for local validation."],
            }
        raise NotImplementedError(f"AI provider '{self.provider}' is not implemented")
