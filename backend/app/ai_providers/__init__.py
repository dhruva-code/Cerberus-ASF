import logging

from app.ai_providers.null_assistant import NullAssistant

logger = logging.getLogger("Cerberus-ASF")

_PROVIDERS = {
    "gemini": "app.ai_providers.gemini:GeminiAssistant",
    "anthropic": "app.ai_providers.anthropic_provider:AnthropicAssistant",
    "openai_compatible": "app.ai_providers.openai_compatible:OpenAICompatibleAssistant",
}


def get_ai_assistant(provider: str, api_key: str, base_url: str = None, model_name: str = None):
    """Factory: returns a configured provider adapter, or NullAssistant if
    no key/provider was given or construction failed for any reason (bad
    key format, SDK import issue, etc.) — AI configuration problems must
    never break a scan, only silently disable the AI-only parts of it."""
    if not api_key or provider not in _PROVIDERS:
        return NullAssistant()

    module_path, class_name = _PROVIDERS[provider].split(":")
    try:
        module = __import__(module_path, fromlist=[class_name])
        provider_cls = getattr(module, class_name)
        return provider_cls(api_key=api_key, base_url=base_url, model_name=model_name)
    except Exception as e:
        logger.error(f"Failed to construct AI provider '{provider}': {e}")
        return NullAssistant()
