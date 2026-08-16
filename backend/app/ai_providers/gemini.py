from google import genai

from app.ai_providers.base import AIAssistantBase

DEFAULT_MODEL = "gemini-3.6-flash"


class GeminiAssistant(AIAssistantBase):
    def __init__(self, api_key: str, model_name: str = None, **_ignored):
        self.client = genai.Client(api_key=api_key)
        self.model_name = model_name or DEFAULT_MODEL
        self.is_configured = True

    def _complete(self, prompt: str) -> str:
        response = self.client.models.generate_content(model=self.model_name, contents=prompt)
        return response.text
