from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from ai.ai_provider import AIProvider, AIRequest


@dataclass
class EnhancedPromptResult:
    original_prompt: str
    enhanced_prompt: str
    used_provider: str
    used_fallback: bool
    context_summary: str | None = None


class PromptEnhancer:
    def __init__(self, provider: AIProvider | None = None) -> None:
        self.provider = provider or AIProvider(provider='mock')

    def enhance(self, prompt: str, context: dict[str, Any] | None = None) -> EnhancedPromptResult:
        original = (prompt or '').strip()
        if not original:
            raise ValueError('Prompt cannot be empty')

        context = context or {}
        context_lines = []
        if context.get('session_id') is not None:
            context_lines.append('Active capture session: ' + str(context.get('session_id')))
        if context.get('packet_count') is not None:
            context_lines.append('Available packets in session/view: ' + str(context.get('packet_count')))
        if context.get('filter'):
            context_lines.append('Active display/filter context: ' + str(context.get('filter')))
        if context.get('alerts'):
            context_lines.append('Detection alerts present: ' + str(context.get('alerts')))
        if context.get('selected_packet_summary'):
            context_lines.append('Selected packet: ' + str(context.get('selected_packet_summary')))

        context_summary = '; '.join(context_lines) if context_lines else None
        system_instructions = (
            'You are a cybersecurity investigation assistant. Enhance the user''s network traffic analysis prompt. '
            'Preserve the original intent. Make it specific, actionable, and evidence-based. '
            'Ask for observed facts vs hypotheses, mention relevant protocols/indicators, and suggest defensive next steps. '
            'Do not invent packet data or specific threats. Keep it concise but thorough.'
        )

        enhanced_prompt_text = None
        used_fallback = False
        used_provider = self.provider.provider

        try:
            if self.provider.provider.lower() != 'mock':
                request = AIRequest(
                    prompt=system_instructions + '\n\nOriginal prompt:\n' + original + '\n\nContext:\n' + (context_summary or 'None') + '\n\nReturn an enhanced, ready-to-use investigation prompt.',
                    evidence=context_lines or None,
                )
                result = self.provider.analyze(request)
                if isinstance(result, dict):
                    summary = result.get('summary') or result.get('enhanced_prompt') or ''
                    if summary and len(summary) > len(original):
                        enhanced_prompt_text = summary
        except Exception:
            used_fallback = True

        if not enhanced_prompt_text:
            used_fallback = True
            base = original
            additions = []
            additions.append('Analyze the available network traffic for unusual communication patterns, suspicious destination IP addresses, unexpected ports, DNS anomalies, and potential indicators of compromise.')
            if context_summary:
                additions.append('Take into account the following context: ' + context_summary + '.')
            additions.append('Explain the evidence for findings, clearly distinguish confirmed observations from hypotheses, cite specific packet/session details where relevant, note limitations, and recommend appropriate defensive investigation steps.')
            enhanced_prompt_text = base + '. ' + ' '.join(additions)

        return EnhancedPromptResult(
            original_prompt=original,
            enhanced_prompt=enhanced_prompt_text,
            used_provider=used_provider,
            used_fallback=used_fallback,
            context_summary=context_summary,
        )
