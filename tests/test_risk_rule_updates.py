"""Startup downloads select validated rules without breaking offline scans."""

import json

import pytest
import requests

from src.CloudPEASS import risk_rule_updates as updates
from src.CloudPEASS import permission_risk_classifier as classifier
from src.k8s import risks as k8s_risks


def _remote_rules(provider):
    if provider == "k8s":
        return {
            "version": 1,
            "provider": provider,
            "rules": [{"id": "fallback", "match": {"always": True}, "severity": "low", "description": "Remote {verb}"}],
        }
    return {
        "version": 1,
        "provider": provider,
        "permission_categories": {"low": [], "medium": [], "high": [], "critical": ["example:Remote"]},
        "combinations": {"critical": [["example:Remote", "example:Other"]], "high": []},
    }


@pytest.fixture(autouse=True)
def reset_selected():
    updates._selected.clear()
    classifier._AWS_RULES = None
    classifier._GCP_RULES = None
    classifier._AZURE_RULES = None
    for name in ("non_permission_identifiers", "severity_overrides", "severity_caps", "load_criticality_combinations", "_singleton_rules", "_catalog_severities"):
        getattr(classifier, name).cache_clear()
    k8s_risks._rules.cache_clear()
    yield
    updates._selected.clear()
    k8s_risks._rules.cache_clear()


@pytest.mark.parametrize("provider", ["aws", "azure", "gcp", "k8s"])
def test_refresh_uses_main_url_and_selected_rules(monkeypatch, tmp_path, provider):
    assert updates.RULES_URL == "https://raw.githubusercontent.com/peass-ng/CloudPEASS/refs/heads/main/src/CloudPEASS/risk_rules"
    monkeypatch.setattr(updates, "_cache_path", lambda name: tmp_path / f"{name}.yaml")
    payload = json.dumps(_remote_rules(provider))
    calls = []

    class Response:
        text = payload
        content = payload.encode()

        def raise_for_status(self):
            pass

    def get(url, timeout):
        calls.append((url, timeout))
        return Response()

    monkeypatch.setattr(updates.requests, "get", get)
    rules = updates.prepare_rules(provider)
    assert calls == [(f"{updates.RULES_URL}/{provider}.yaml", 8)]
    assert rules == _remote_rules(provider)
    assert (tmp_path / f"{provider}.yaml").read_text() == payload
    if provider == "k8s":
        assert k8s_risks._rules()[0]["description"] == "Remote {verb}"
    else:
        assert classifier._load_yaml(provider) == rules
        assert classifier.load_criticality_combinations(provider)["critical"] == (("example:Remote", "example:Other"),)
        assert classifier.classify_permission(provider, "example:Remote") == "critical"


def test_failed_download_uses_valid_cache(monkeypatch, tmp_path):
    cache = tmp_path / "aws.yaml"
    cache.write_text(json.dumps(_remote_rules("aws")))
    monkeypatch.setattr(updates, "_cache_path", lambda name: cache)
    monkeypatch.setattr(updates.requests, "get", lambda *a, **k: (_ for _ in ()).throw(requests.ConnectionError("offline")))
    assert updates.prepare_rules("aws")["permission_categories"]["critical"] == ["example:Remote"]


def test_bad_download_and_bad_cache_use_bundled_rules(monkeypatch, tmp_path):
    cache = tmp_path / "aws.yaml"
    cache.write_text("[")
    monkeypatch.setattr(updates, "_cache_path", lambda name: cache)

    invalid_rules = _remote_rules("aws")
    invalid_rules["write_like_prefix_regex"] = "["

    class Response:
        text = json.dumps(invalid_rules)
        content = text.encode()

        def raise_for_status(self):
            pass

    monkeypatch.setattr(updates.requests, "get", lambda *a, **k: Response())
    assert "iam:PassRole" in updates.prepare_rules("aws")["critical_exact"]


def test_no_update_skips_network_and_cache(monkeypatch, tmp_path):
    cache = tmp_path / "aws.yaml"
    cache.write_text(json.dumps(_remote_rules("aws")))
    monkeypatch.setattr(updates, "_cache_path", lambda name: cache)
    monkeypatch.setattr(updates.requests, "get", lambda *a, **k: pytest.fail("network used"))
    assert "iam:PassRole" in updates.prepare_rules("aws", update=False)["critical_exact"]
