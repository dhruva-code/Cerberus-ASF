import logging
import os

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

SKIP_FILENAMES = {"R.java", "BuildConfig.java"}
MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024
MAX_CODE_SNIPPET_CHARS = 300


class ASTAnalyzer:
    """Runs tree-sitter structural rules and field-secret detection over a
    jadx-decompiled Java source tree."""

    def __init__(self):
        self.parser = get_parser("java")
        self.language = get_language("java")
        self._compiled_rules = []
        for rule in AST_RULES:
            compiled_queries = [Query(self.language, q) for q in rule["queries"]]
            self._compiled_rules.append((rule, compiled_queries))
        self._secret_query = Query(self.language, SECRET_FIELD_QUERY)

    def scan_directory(self, sources_dir: str, package_name: str = ""):
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
