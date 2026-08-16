import openai

from app.ai_providers.base import AIAssistantBase

DEFAULT_MODEL = "gpt-4o-mini"


class OpenAICompatibleAssistant(AIAssistantBase):
    """Covers OpenAI itself (base_url=None falls back to api.openai.com) and
    any third-party host that implements the same chat-completions schema
    (Azure OpenAI, OpenRouter, Groq, Together, local Ollama/LM Studio, etc.)
    — which provider it's actually talking to is entirely a function of
    what base_url the user supplies."""

    def __init__(self, api_key: str, base_url: str = None, model_name: str = None, **_ignored):
        self.client = openai.OpenAI(api_key=api_key, base_url=base_url or None)
        self.model_name = model_name or DEFAULT_MODEL
        self.is_configured = True

    def _complete(self, prompt: str) -> str:
        response = self.client.chat.completions.create(
            model=self.model_name,
            messages=[{"role": "user", "content": prompt}],
        )
        return response.choices[0].message.content
