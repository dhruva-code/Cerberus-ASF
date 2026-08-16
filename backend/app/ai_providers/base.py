"""
Shared AI-assistant logic: prompt templates, JSON extraction/parsing, and
graceful degradation on any failure (never raise out to the caller — a
broken AI call should never break a static scan). Ported verbatim from
the original single-provider ai_engine.py.

Provider adapters (gemini.py, anthropic.py, openai_compatible.py) only
need to implement `_complete(prompt) -> str`.
"""

import json
import logging
import re
import time

logger = logging.getLogger("Cerberus-ASF")

_JSON_OBJECT_FENCE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
_JSON_OBJECT_BARE = re.compile(r"(\{.*?\})", re.DOTALL)
_JSON_ARRAY_FENCE = re.compile(r"```json\s*(\[.*?\])\s*```", re.DOTALL)
_JSON_ARRAY_BARE = re.compile(r"(\[.*?\])", re.DOTALL)


class AIAssistantBase:
    is_configured = False
    model_name = "None"

    def _complete(self, prompt: str) -> str:
        """Sends prompt to the provider, returns the raw text response."""
        raise NotImplementedError

    def _complete_with_retry(self, prompt: str, max_retries: int = 3) -> str:
        for attempt in range(max_retries):
            try:
                return self._complete(prompt)
            except Exception as e:
                error_msg = str(e)
                is_rate_limited = any(
                    marker in error_msg for marker in ("429", "RESOURCE_EXHAUSTED", "rate_limit")
                ) or "rate limit" in error_msg.lower()
                if is_rate_limited and attempt < max_retries - 1:
                    wait_time = 25 * (attempt + 1)
                    logger.warning(f"AI API Rate limit hit. Sleeping for {wait_time}s before retry {attempt+1}/{max_retries}...")
                    time.sleep(wait_time)
                    continue
                raise e

    @staticmethod
    def _extract_json(result: str, fence_pattern, bare_pattern) -> str:
        match = fence_pattern.search(result)
        if match:
            return match.group(1)
        match = bare_pattern.search(result)
        if match:
            return match.group(1)
        return result

    def verify_finding(self, issue_title: str, code_snippet: str) -> dict:
        """Verifies if a structural finding is a true positive based on context."""
        if not self.is_configured:
            return {"verified": True, "confidence": 1.0, "reason": "AI not configured."}

        prompt = f"""
        You are an expert Android security auditor. Review the following code snippet which triggered a static analysis rule for: "{issue_title}".
        Determine if this is a True Positive (an actual security risk) or a False Positive (safe usage, sanitized, or test code).

        Code Snippet:
        {code_snippet}

        Respond ONLY with a valid JSON object matching this schema, no markdown, no backticks:
        {{"verified": true/false, "confidence": 0.9, "reason": "short explanation"}}
        """

        result = ""
        try:
            result = self._complete_with_retry(prompt).strip()
            if not result:
                return {"verified": True, "confidence": 1.0, "reason": "AI Error: Empty response from model"}
            result = self._extract_json(result, _JSON_OBJECT_FENCE, _JSON_OBJECT_BARE)
            return json.loads(result)
        except json.JSONDecodeError as e:
            logger.error(f"AI Verification JSON parsing failed: {e}. Raw response: {result}")
            return {"verified": True, "confidence": 1.0, "reason": "AI Error: Invalid JSON returned by model"}
        except Exception as e:
            logger.error(f"AI Verification failed: {e}")
            return {"verified": True, "confidence": 1.0, "reason": f"AI Error: {e}"}

    def verify_secret(self, secret_type: str, secret_value: str, context: str) -> dict:
        """Verifies if an extracted secret is real or dummy based on context."""
        if not self.is_configured:
            return {"verified": True, "confidence": 1.0, "reason": "AI not configured."}

        prompt = f"""
        You are an expert security auditor. We found a potential "{secret_type}" with value "{secret_value}".
        Based on the surrounding code context, is this a real production secret or a dummy/test value?

        Context:
        {context}

        Respond ONLY with a valid JSON object matching this schema, no markdown, no backticks:
        {{"verified": true/false, "confidence": 0.9, "reason": "short explanation"}}
        """

        result = ""
        try:
            result = self._complete_with_retry(prompt).strip()
            if not result:
                return {"verified": True, "confidence": 1.0, "reason": "AI Error: Empty response from model"}
            result = self._extract_json(result, _JSON_OBJECT_FENCE, _JSON_OBJECT_BARE)
            return json.loads(result)
        except json.JSONDecodeError as e:
            logger.error(f"AI Secret Verification JSON parsing failed: {e}. Raw response: {result}")
            return {"verified": True, "confidence": 1.0, "reason": "AI Error: Invalid JSON returned"}
        except Exception as e:
            logger.error(f"AI Secret Verification failed: {e}")
            return {"verified": True, "confidence": 1.0, "reason": f"AI Error: {e}"}

    def deep_scan_source(self, filename: str, source_code: str) -> list:
        """Performs a semantic deep scan of a decompiled Java/Kotlin file."""
        if not self.is_configured:
            return []

        prompt = f"""
        You are an expert Android security researcher. Analyze the following decompiled source code for logical vulnerabilities (e.g., IDOR, deep link hijacking, weak custom crypto, intent spoofing, auth bypass).

        File: {filename}

        Source Code:
        {source_code}

        Respond ONLY with a valid JSON array of vulnerability objects. If no vulnerabilities, return []. No markdown, no backticks.
        Schema per finding:
        [{{"title": "...", "severity": "HIGH/MEDIUM/LOW", "description": "...", "remediation": "...", "line": "..."}}]
        """

        result = ""
        try:
            result = self._complete_with_retry(prompt).strip()
            if not result:
                return []
            result = self._extract_json(result, _JSON_ARRAY_FENCE, _JSON_ARRAY_BARE)
            findings = json.loads(result)
            return findings if isinstance(findings, list) else []
        except json.JSONDecodeError as e:
            logger.error(f"AI Deep Scan JSON parsing failed: {e}. Raw response: {result}")
            return []
        except Exception as e:
            logger.error(f"AI Deep Scan failed: {e}")
            return []
