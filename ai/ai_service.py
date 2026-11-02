from __future__ import annotations

from ai.ai_provider import AIProvider, AIRequest


class AIService:
    def __init__(self, provider: str = "mock", api_key: str | None = None) -> None:
        self.provider = AIProvider(provider=provider, api_key=api_key)

    def summarize_packet(self, packet_summary: str) -> dict[str, object]:
        return self.provider.analyze(AIRequest(prompt="Summarize packet analysis", evidence=[packet_summary]))
