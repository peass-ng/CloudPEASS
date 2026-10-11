"""Fetch and select the canonical permission rules for one scan."""

from __future__ import annotations

import os
import re
import string
import tempfile
from pathlib import Path

import requests
import yaml


RULES_URL = (
    "https://raw.githubusercontent.com/carlospolop/CloudPEASS/"
    "refs/heads/main/src/CloudPEASS/risk_rules"
)
PROVIDERS = frozenset({"aws", "azure", "gcp", "k8s"})
LEVELS = frozenset({"low", "medium", "high", "critical"})
K8S_FIELDS = frozenset({"verb", "resource", "subresource", "group", "full", "namespace", "name", "path", "non_resource_url", "mode", "delegated_verb"})
_selected: dict[str, dict] = {}


def _bundled_path(provider: str) -> Path:
    return Path(__file__).resolve().parent / "risk_rules" / f"{provider}.yaml"


def _cache_path(provider: str) -> Path:
    return Path.home() / ".cache" / "cloudpeass" / "risk_rules" / f"{provider}.yaml"


def _validate_match(match: object) -> None:
    if not isinstance(match, dict):
        raise ValueError("Invalid Kubernetes match")
    if set(match) == {"always"} and isinstance(match["always"], bool):
        return
    if set(match) in ({"all"}, {"any"}) and isinstance(next(iter(match.values())), list):
        for child in next(iter(match.values())):
            _validate_match(child)
        return
    if set(match) == {"not"}:
        _validate_match(match["not"])
        return
    if match.get("field") not in K8S_FIELDS:
        raise ValueError("Invalid Kubernetes match field")
    op = match.get("op")
    if op == "truthy" and set(match) == {"field", "op"}:
        return
    if set(match) != {"field", "op", "value"}:
        raise ValueError("Invalid Kubernetes match keys")
    value = match["value"]
    if op in {"eq", "ne", "contains", "prefix", "suffix"} and isinstance(value, str):
        return
    if op in {"in", "not_in", "prefix", "suffix"} and isinstance(value, list) and all(isinstance(v, str) for v in value):
        return
    raise ValueError("Invalid Kubernetes match operator")


def _parse(text: str, provider: str) -> dict:
    data = yaml.safe_load(text)
    if not isinstance(data, dict) or data.get("provider") != provider or data.get("version") != 1:
        raise ValueError("Unsupported permission rules schema")
    if provider == "k8s":
        rules = data.get("rules")
        if not isinstance(rules, list) or not rules or not isinstance(rules[-1], dict) or rules[-1].get("match") != {"always": True}:
            raise ValueError("Kubernetes rules need a final fallback")
        ids = set()
        for rule in rules:
            if not isinstance(rule, dict) or not isinstance(rule.get("id"), str) or rule["id"] in ids:
                raise ValueError("Invalid Kubernetes rule ID")
            ids.add(rule["id"])
            _validate_match(rule.get("match"))
            if rule.get("severity") not in LEVELS | {"delegated"}:
                raise ValueError("Invalid Kubernetes severity")
            if rule["severity"] == "delegated":
                severities = rule.get("delegated_severities")
                if not isinstance(severities, dict) or set(severities) != LEVELS or any(value not in LEVELS for value in severities.values()):
                    raise ValueError("Invalid delegated severities")
            if "severity_when" in rule:
                conditional = rule["severity_when"]
                if not isinstance(conditional, dict) or conditional.get("severity") not in LEVELS:
                    raise ValueError("Invalid conditional severity")
                _validate_match(conditional.get("match"))
            description = rule.get("description")
            if not isinstance(description, str):
                raise ValueError("Invalid Kubernetes description")
            for _, field, spec, conversion in string.Formatter().parse(description):
                if field is not None and (field not in K8S_FIELDS or spec or conversion):
                    raise ValueError("Invalid Kubernetes description field")
    else:
        categories = data.get("permission_categories")
        combos = data.get("combinations")
        if not isinstance(categories, dict) or set(categories) != LEVELS or not isinstance(combos, dict):
            raise ValueError("Missing permission categories or combinations")
        seen = {}
        for level, permissions in categories.items():
            if not isinstance(permissions, list):
                raise ValueError("Invalid permission categories")
            for permission in permissions:
                if not isinstance(permission, str) or not permission.strip():
                    raise ValueError("Invalid permission")
                key = permission.casefold() if provider in {"aws", "azure"} else permission
                if key in seen and seen[key] != level:
                    raise ValueError("Conflicting permission categories")
                seen[key] = level
        for level in ("critical", "high"):
            values = combos.get(level)
            if not isinstance(values, list) or any(not isinstance(c, list) or not c or any(not isinstance(p, str) or not p.strip() for p in c) for c in values):
                raise ValueError("Invalid permission combinations")
        overrides = data.get("severity_overrides", {})
        if not isinstance(overrides, dict):
            raise ValueError("Invalid severity overrides")
        for permission, level in overrides.items():
            if not isinstance(permission, str) or not permission.strip() or level not in LEVELS:
                raise ValueError("Invalid severity override")
            key = permission.casefold() if provider in {"aws", "azure"} else permission
            if key in seen and seen[key] != level:
                raise ValueError("Conflicting severity override")
        for name, value in data.items():
            if name.endswith("_regex"):
                for expression in value if isinstance(value, list) else [value]:
                    re.compile(expression)
    return data


def selected_rules(provider: str) -> dict:
    """Return rules chosen at startup, or the bundled baseline for library callers."""
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")
    if provider not in _selected:
        return _parse(_bundled_path(provider).read_text(encoding="utf-8"), provider)
    return _selected[provider]


def prepare_rules(provider: str, *, update: bool = True) -> dict:
    """Try main on every invocation, then cache, then the bundled baseline."""
    if provider not in PROVIDERS:
        raise ValueError(f"Unknown provider: {provider}")
    if update:
        try:
            response = requests.get(f"{RULES_URL}/{provider}.yaml", timeout=8)
            response.raise_for_status()
            if len(response.content) > 5_000_000:
                raise ValueError("Permission rules exceed size limit")
            data = _parse(response.text, provider)
            _selected[provider] = data
            cache_path = _cache_path(provider)
            try:
                cache_path.parent.mkdir(parents=True, exist_ok=True)
                with tempfile.NamedTemporaryFile("w", encoding="utf-8", dir=cache_path.parent, prefix=f".{provider}-", delete=False) as handle:
                    temp_path = Path(handle.name)
                try:
                    temp_path.write_text(response.text, encoding="utf-8")
                    os.replace(temp_path, cache_path)
                finally:
                    temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            return data
        except (requests.RequestException, ValueError, TypeError, KeyError, re.error, yaml.YAMLError, OSError) as exc:
            print(f"Warning: Could not refresh {provider} permission rules: {exc}")
        try:
            data = _parse(_cache_path(provider).read_text(encoding="utf-8"), provider)
            _selected[provider] = data
            return data
        except (OSError, ValueError, TypeError, KeyError, re.error, yaml.YAMLError):
            pass
    data = _parse(_bundled_path(provider).read_text(encoding="utf-8"), provider)
    _selected[provider] = data
    return data
