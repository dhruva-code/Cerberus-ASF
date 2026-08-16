from app.ai_providers.base import AIAssistantBase


class NullAssistant(AIAssistantBase):
    """Used when no provider is configured, an unrecognized provider name
    was given, or constructing the real adapter failed (bad key format,
    SDK error, etc.) — preserves "AI problems never break a scan": every
    method just returns the same permissive defaults the base class
    already returns for is_configured=False."""

    is_configured = False
    model_name = "None"
