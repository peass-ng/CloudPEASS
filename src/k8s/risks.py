"""Classify Kubernetes RBAC with the canonical HackTricks Cloud ordered rules."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

from .models import PermissionKey


def _rules_path() -> Path:
    return Path(__file__).resolve().parent.parent / "CloudPEASS" / "risk_rules" / "k8s.yaml"


@lru_cache(maxsize=1)
def _rules() -> tuple[dict, ...]:
    data = yaml.safe_load(_rules_path().read_text(encoding="utf-8"))
    if data.get("version") != 1 or data.get("provider") != "k8s":
        raise ValueError("Unsupported Kubernetes permission rules")
    return tuple(data["rules"])


def _matches(match: dict, context: dict) -> bool:
    if "always" in match:
        return match["always"]
    if "all" in match:
        return all(_matches(item, context) for item in match["all"])
    if "any" in match:
        return any(_matches(item, context) for item in match["any"])
    if "not" in match:
        return not _matches(match["not"], context)
    actual = context[match["field"]]
    expected = match.get("value")
    operation = match["op"]
    if operation == "truthy":
        return bool(actual)
    if operation == "eq":
        return actual == expected
    if operation == "ne":
        return actual != expected
    if operation == "in":
        return actual in expected
    if operation == "not_in":
        return actual not in expected
    if operation == "contains":
        return expected in actual
    if operation == "prefix":
        return actual.startswith(tuple(expected) if isinstance(expected, list) else expected)
    if operation == "suffix":
        return actual.endswith(tuple(expected) if isinstance(expected, list) else expected)
    raise ValueError(f"Unsupported Kubernetes match operation: {operation}")


def classify_permission(key: PermissionKey) -> tuple[str, str]:
    verb, resource, subresource, group = (value.lower() for value in
                                        (key.verb, key.resource, key.subresource, key.group))
    context = dict(verb=verb, resource=resource, subresource=subresource, group=group,
                   full=f"{resource}/{subresource}" if subresource else resource,
                   namespace=key.namespace, name=key.name, path=key.non_resource_url.lower(),
                   non_resource_url=key.non_resource_url, mode=verb.partition(":")[2],
                   delegated_verb=verb.rsplit(":", 1)[-1])
    for rule in _rules():
        if not _matches(rule["match"], context):
            continue
        severity = rule["severity"]
        conditional = rule.get("severity_when")
        if conditional and _matches(conditional["match"], context):
            severity = conditional["severity"]
        if severity == "delegated":
            delegated_key = PermissionKey(verb=context["delegated_verb"], group=key.group,
                                          version=key.version, resource=key.resource,
                                          subresource=key.subresource, namespace=key.namespace,
                                          name=key.name)
            delegated_severity, _ = classify_permission(delegated_key)
            severity = rule["delegated_severities"][delegated_severity]
        return severity, rule["description"].format_map(context)
    raise ValueError("Kubernetes rules must include a final fallback")
