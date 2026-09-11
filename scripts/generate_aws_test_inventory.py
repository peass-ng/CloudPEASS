#!/usr/bin/env python3
"""Regenerate the complete known-positive AWS permission inventory."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

import CloudPEASS.permission_risk_classifier as risk_classifier  # noqa: E402
from sensitive_permissions.aws import (  # noqa: E402
    hacktricks_pr_heading_exclusions,
    hacktricks_reconciled_true_positive_actions,
    live_validated_disclosure_documentation,
    sensitive_combinations,
    very_sensitive_combinations,
)


DOCUMENT = ROOT / "docs" / "AWS-cross-service-security-review.md"
BEGIN = "<!-- BEGIN GENERATED KNOWN-POSITIVE AWS TEST INVENTORY -->"
END = "<!-- END GENERATED KNOWN-POSITIVE AWS TEST INVENTORY -->"
HACKTRICKS_REVISION = "bcd4ee49928fa5bc053f82cd966e2cb7d85177e9"
HACKTRICKS_ROOT = (
    "https://github.com/HackTricks-wiki/hacktricks-cloud/blob/"
    f"{HACKTRICKS_REVISION}/src/pentesting-cloud/aws-security"
)


def _bundled_classifications() -> dict[str, str]:
    """Classify deterministically from the bundled rules, not a user cache."""
    with tempfile.TemporaryDirectory() as temporary_directory:
        risk_classifier._AWS_RULES = None
        original_cache_dir = risk_classifier._cache_dir
        original_download = risk_classifier._download_risk_rules
        try:
            risk_classifier._cache_dir = lambda: Path(temporary_directory)
            risk_classifier._download_risk_rules = lambda _provider: None
            return {
                action: risk_classifier.classify_permission(
                    "aws", action, unknown_default="medium"
                )
                for action in live_validated_disclosure_documentation
            }
        finally:
            risk_classifier._AWS_RULES = None
            risk_classifier._cache_dir = original_cache_dir
            risk_classifier._download_risk_rules = original_download


def _registration(action: str) -> str:
    critical_singletons = {
        combination[0]
        for combination in very_sensitive_combinations
        if len(combination) == 1
    }
    high_singletons = {
        combination[0]
        for combination in sensitive_combinations
        if len(combination) == 1
    }
    critical_members = {
        permission
        for combination in very_sensitive_combinations
        if len(combination) > 1
        for permission in combination
    }
    high_members = {
        permission
        for combination in sensitive_combinations
        if len(combination) > 1
        for permission in combination
    }
    if action in critical_singletons:
        return "standalone Critical"
    if action in high_singletons:
        return "standalone High"
    if action in critical_members:
        return "Critical combination"
    if action in high_members:
        return "High combination"
    return "observed Medium effect"


def render() -> str:
    classifications = _bundled_classifications()
    counts = Counter(classifications.values())
    rows = []
    for action in sorted(live_validated_disclosure_documentation, key=str.lower):
        evidence = live_validated_disclosure_documentation[action]
        provenance = (
            "HackTricks reconciliation"
            if action in hacktricks_reconciled_true_positive_actions
            else "CloudPEASS validation"
        )
        rows.append(
            f"| `{action}` | {classifications[action].title()} | "
            f"{_registration(action)} | {provenance} | "
            f"[`{evidence}`]({HACKTRICKS_ROOT}/{evidence}) |"
        )

    exclusion_rows = [
        f"| `{action}` | {reason} |"
        for action, reason in sorted(hacktricks_pr_heading_exclusions.items())
    ]

    return "\n".join(
        [
            BEGIN,
            "",
            "## Complete known-positive AWS permission inventory",
            "",
            "This generated inventory complements X001-X119 above. It includes every permission with retained CloudPEASS live evidence plus true-positive gaps reconciled from the accumulated HackTricks Cloud AWS PR. Negative controls, cleanup-only actions, and hypotheses without an observed security effect are excluded. A `combination` registration means the permission is not promoted to that severity by itself; all documented companion permissions and prerequisites remain necessary.",
            "",
            "The wider HackTricks AWS privilege-escalation, post-exploitation, and persistence heading audit found no additional unregistered permissions that classify High or Critical. These permission-shaped headings from the active AWS documentation PR are intentionally excluded from the positive inventory:",
            "",
            "| Excluded PR heading | Reason |",
            "| --- | --- |",
            *exclusion_rows,
            "",
            f"Inventory total: **{len(rows)} permissions** — "
            f"**{counts['critical']} Critical**, **{counts['high']} High**, "
            f"**{counts['medium']} Medium**, and **{counts['low']} Low** when each "
            "permission is classified alone.",
            "",
            "| Permission | Standalone classifier | Attack registration | Provenance | Evidence |",
            "| --- | --- | --- | --- | --- |",
            *rows,
            "",
            END,
        ]
    )


def updated_document() -> str:
    current = DOCUMENT.read_text(encoding="utf-8")
    generated = render()
    if BEGIN in current or END in current:
        if current.count(BEGIN) != 1 or current.count(END) != 1:
            raise SystemExit("inventory markers are incomplete or duplicated")
        prefix, remainder = current.split(BEGIN, 1)
        _, suffix = remainder.split(END, 1)
        return prefix.rstrip() + "\n\n" + generated + suffix
    return current.rstrip() + "\n\n" + generated + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check", action="store_true", help="fail if the inventory is stale"
    )
    args = parser.parse_args()
    expected = updated_document()
    current = DOCUMENT.read_text(encoding="utf-8")
    if args.check:
        if current != expected:
            print(f"{DOCUMENT.relative_to(ROOT)} is stale", file=sys.stderr)
            return 1
        return 0
    DOCUMENT.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
