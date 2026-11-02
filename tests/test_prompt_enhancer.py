from __future__ import annotations

from ai.prompt_enhancer import PromptEnhancer
from ai.ai_provider import AIProvider


def test_enhance_empty_prompt_raises():
    enhancer = PromptEnhancer()
    try:
        enhancer.enhance('')
        assert False
    except ValueError:
        pass


def test_enhance_without_context():
    enhancer = PromptEnhancer()
    result = enhancer.enhance('analyze this traffic')
    assert result.original_prompt == 'analyze this traffic'
    assert result.enhanced_prompt
    assert 'analyze' in result.enhanced_prompt.lower()


def test_enhance_with_context():
    enhancer = PromptEnhancer()
    result = enhancer.enhance('check for anomalies', {'session_id': 1, 'packet_count': 100})
    assert result.context_summary
    assert result.enhanced_prompt
