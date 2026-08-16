import anthropic

from app.ai_providers.base import AIAssistantBase

DEFAULT_MODEL = "claude-sonnet-5"
MAX_TOKENS = 4096


class AnthropicAssistant(AIAssistantBase):
    def __init__(self, api_key: str, model_name: str = None, **_ignored):
        self.client = anthropic.Anthropic(api_key=api_key)
        self.model_name = model_name or DEFAULT_MODEL
        self.is_configured = True

    def _complete(self, prompt: str) -> str:
        response = self.client.messages.create(
            model=self.model_name,
            max_tokens=MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.content[0].text
