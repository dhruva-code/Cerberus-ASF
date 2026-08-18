import logging
import os
import time

from tree_sitter import Query, QueryCursor
from tree_sitter_language_pack import get_parser, get_language

from app.rules.structural_rules import AST_RULES
from app.rules.secret_rules import (
    SECRET_FIELD_QUERY,
    MIN_VALUE_LENGTH,
    matched_sensitive_tokens,
    looks_like_self_naming_key,
    classify_severity,
)
from app.provenance import classify as classify_provenance

logger = logging.getLogger("Cerberus-ASF")

SKIP_FILENAMES = {"R.java", "BuildConfig.java"}
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024
MAX_CODE_SNIPPET_CHARS = 300


class ASTAnalyzer:
    """Runs tree-sitter structural rules and field-secret detection over a
    jadx-decompiled Java source tree.

    tree_sitter_language_pack does not ship compiled grammars in its wheel —
    get_parser()/get_language() download a ~22MB bundle from GitHub Releases
    on first use per machine, caching it under ~/.cache/tree-sitter-
    language-pack/. On a network that can't reach GitHub cleanly (proxy,
    firewall, VPN not yet up, a flaky link — all common on the
    security-testing distros/networks this tool targets), that download
    times out and previously raised straight out of this constructor, which
    is called eagerly at FastAPI module-import time (app/main.py:
    `static_engine = StaticAnalyzer()`) — so a single transient network hit
    took the *entire* server down before it could even start listening, not
    just this one feature. This is now caught here and degrades to
    "AST/structural analysis unavailable" instead, matching how a missing
    jadx or trufflehog is already handled elsewhere in this module."""

    def __init__(self):
        self.available = False
        self.unavailable_reason = None
        self.parser = None
        self.language = None
        self._compiled_rules = []
        self._secret_query = None

        last_error = None
        for attempt in range(2):  # one retry — the failure mode is a one-shot network download, often transient
            try:
                self.parser = get_parser("java")
                self.language = get_language("java")
                break
            except Exception as e:
                last_error = e
                if attempt == 0:
                    logger.warning(f"tree-sitter Java grammar load failed (attempt 1/2), retrying: {e}")
                    time.sleep(2)

        if self.parser is None or self.language is None:
            self.unavailable_reason = str(last_error)
            logger.error(
                "AST-based static analysis DISABLED — could not load the tree-sitter Java grammar "
                f"after 2 attempts ({last_error}). This is almost always a network problem: "
                "tree-sitter-language-pack downloads compiled grammars from GitHub on first use "
                "and caches them in ~/.cache/tree-sitter-language-pack/. Check outbound access to "
                "github.com/objects.githubusercontent.com (proxy/firewall/VPN), then either restart "
                "the server to retry, or pre-warm the cache with: "
                "backend/venv/bin/python3 -c \"from tree_sitter_language_pack import get_parser; get_parser('java')\". "
                "Static analysis will continue to run — manifest, certificate, and regex/TruffleHog "
                "secret detection are all unaffected — but structural code findings (weak crypto, "
                "SQL injection, insecure logging, etc.) and AST-based secret-field detection will be "
                "skipped until this is resolved."
            )
            return

        try:
            for rule in AST_RULES:
                compiled_queries = [Query(self.language, q) for q in rule["queries"]]
                self._compiled_rules.append((rule, compiled_queries))
            self._secret_query = Query(self.language, SECRET_FIELD_QUERY)
            self.available = True
        except Exception as e:
            # A grammar/query mismatch would be a packaging bug, not a network
            # blip — still shouldn't crash the whole server over it.
            self.unavailable_reason = str(e)
            logger.error(f"AST-based static analysis DISABLED — failed to compile structural rule queries: {e}")

    def scan_directory(self, sources_dir: str, package_name: str = ""):
        if not self.available:
            return [], []

        findings, secrets = [], []
        for root, _, files in os.walk(sources_dir):
            for fname in files:
                if not fname.endswith(".java") or fname in SKIP_FILENAMES:
                    continue
                path = os.path.join(root, fname)
                try:
                    if os.path.getsize(path) > MAX_FILE_SIZE_BYTES:
                        continue
                    with open(path, "rb") as f:
                        source_bytes = f.read()
                    tree = self.parser.parse(source_bytes)
                except Exception as e:
                    logging.debug(f"AST scan skipped {path}: {e}")
                    continue

                rel_path = os.path.relpath(path, sources_dir)
                scope = classify_provenance(package_name, rel_path)
                findings.extend(self._run_structural_rules(tree, source_bytes, rel_path, scope))
                secrets.extend(self._run_secret_rule(tree, source_bytes, rel_path, scope))
        return findings, secrets

    def _run_structural_rules(self, tree, source_bytes, rel_path, scope):
        results = []
        lines = source_bytes.splitlines()
        for rule, compiled_queries in self._compiled_rules:
            seen_lines = set()
            for query in compiled_queries:
                cursor = QueryCursor(query)
                for _pattern_index, captures in cursor.matches(tree.root_node):
                    node = captures.get("call", [None])[0]
                    if node is None:
                        continue
                    start_row, end_row = node.start_point[0], node.end_point[0]
                    line = start_row + 1
                    if line in seen_lines:
                        continue
                    seen_lines.add(line)

                    snippet = b"\n".join(lines[start_row:end_row + 1]).decode("utf-8", errors="replace").strip()
                    finding = {k: v for k, v in rule.items() if k != "queries"}
                    finding["target"] = rel_path
                    finding["line"] = line
                    finding["code"] = snippet[:MAX_CODE_SNIPPET_CHARS]
                    finding["scope"] = scope
                    results.append(finding)
        return results

    def _run_secret_rule(self, tree, source_bytes, rel_path, scope):
        results = []
        cursor = QueryCursor(self._secret_query)
        for _pattern_index, captures in cursor.matches(tree.root_node):
            fname_node = captures.get("fname", [None])[0]
            fvalue_node = captures.get("fvalue", [None])[0]
            if fname_node is None or fvalue_node is None:
                continue

            field_name = fname_node.text.decode("utf-8", errors="replace")
            if not matched_sensitive_tokens(field_name):
                continue

            raw_value = fvalue_node.text.decode("utf-8", errors="replace")
            value = raw_value[1:-1] if raw_value.startswith('"') and raw_value.endswith('"') and len(raw_value) >= 2 else raw_value
            if len(value) < MIN_VALUE_LENGTH:
                continue
            if looks_like_self_naming_key(field_name, value):
                continue

            results.append({
                "type": f"Hardcoded Secret Field ('{field_name}')",
                "value": value,
                "severity": classify_severity(field_name),
                "file": rel_path,
                "line": fname_node.start_point[0] + 1,
                "scope": scope,
            })
        return results
