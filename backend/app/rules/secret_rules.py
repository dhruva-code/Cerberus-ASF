"""
Field-level hardcoded secret detection.

Regex over raw bytes can only catch API-key-shaped tokens (base64/hex-ish
strings). It structurally can't catch a real-world case like:

    private static String key = "This is the super secret key 123";

because the "secret" here is a natural-language string, not a token. This
rule instead looks at *how a string literal is used* (assigned to a field
whose name suggests a credential) rather than what the literal looks like.

Two false-positive traps this module deliberately guards against:

1. Unanchored substring matching on the field name. A naive
   `"iv" in name.lower()` matches "INTERACTIVE", "DIVING", "ACTIVE" —
   and bare "key" matches "HOCKEY". Field names must be tokenized
   (camelCase/snake_case aware) and a token must match *exactly*.

2. Android's own `KEY_X = "x"` naming idiom. Bundle/Intent-extra and
   analytics-event constants are conventionally named `KEY_LABEL`,
   `EVENT_KEY`, etc., with a value that just echoes the constant's own
   purpose as a lookup key ("label", "event") — not a credential. This
   is a *real* whole-word match on "key" (not a substring bug), so
   tokenization alone doesn't fix it; see looks_like_self_naming_key().
"""

import re

SECRET_FIELD_QUERY = """
(field_declaration
  type: (_) @ftype
  declarator: (variable_declarator
    name: (identifier) @fname
    value: (string_literal) @fvalue))
"""

SENSITIVE_TOKENS = {"key", "secret", "password", "token", "iv", "credential"}

SEVERITY_BY_TOKEN = {
    "password": "HIGH", "secret": "HIGH", "credential": "HIGH",
    "token": "HIGH", "key": "HIGH", "iv": "MEDIUM",
}

MIN_VALUE_LENGTH = 4

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])")
_NON_ALNUM = re.compile(r"[^A-Za-z0-9]+")


def tokenize(identifier: str) -> list:
    """Splits a camelCase/snake_case/SCREAMING_SNAKE_CASE identifier into
    lowercase word tokens, e.g. "KEY_CallToActionId" -> ["key", "call",
    "to", "action", "id"]."""
    spaced = _CAMEL_BOUNDARY.sub("_", identifier)
    return [t.lower() for t in _NON_ALNUM.split(spaced) if t]


def matched_sensitive_tokens(field_name: str) -> list:
    return [t for t in tokenize(field_name) if t in SENSITIVE_TOKENS]


def _is_token_suffix(shorter: list, longer: list) -> bool:
    return bool(shorter) and len(shorter) <= len(longer) and longer[-len(shorter):] == shorter


def looks_like_self_naming_key(field_name: str, value: str) -> bool:
    """True when the field looks like Android's "KEY_X = 'x'" bundle/intent
    -extra or analytics-event naming idiom rather than an actual secret:
    the descriptive part of the name (with the sensitive token itself
    removed) matches the tail of the value's own tokens — either a short
    direct echo ("KEY_LABEL" / "label") or a namespaced constant string
    ("KEY_TITLE" / "com.google.android.gms.cast.metadata.TITLE").

    Token-level suffix matching (not raw substring) is deliberate: a
    substring check would also suppress a genuine secret like
    "ENCRYPTION_KEY" = "MyEncryptionKeyValue123" just because "encryption"
    happens to appear inside the value — token suffix matching requires
    the whole trailing token(s) to line up, not an incidental fragment.

    A field name that's *only* the bare sensitive token (e.g. plain "key"
    or "secret", nothing else) is never suppressed here — that's the
    strongest, most direct signal of a real credential field."""
    tokens = tokenize(field_name)
    remaining = [t for t in tokens if t not in SENSITIVE_TOKENS]
    if not remaining:
        return False

    value_tokens = tokenize(value)
    if not value_tokens:
        return False

    return _is_token_suffix(remaining, value_tokens) or _is_token_suffix(value_tokens, remaining)


def classify_severity(field_name: str) -> str:
    for token in matched_sensitive_tokens(field_name):
        if token in SEVERITY_BY_TOKEN:
            return SEVERITY_BY_TOKEN[token]
    return "MEDIUM"
