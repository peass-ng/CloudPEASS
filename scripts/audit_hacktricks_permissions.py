#!/usr/bin/env python3
"""Inventory documented permission identifiers for an offline classification review.

This is a coverage tool, not an automatic severity judge. It never calls a cloud
API or executes examples from the book. Abbreviations, commands and permission
wildcards need contextual review; they are not expanded into guessed grants.
"""
from __future__ import annotations
import argparse
import csv
from collections import Counter, defaultdict
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from CloudPEASS.permission_risk_classifier import (  # noqa: E402
    classify_permission, is_non_permission, severity_override,
)

PATTERNS = {
    'aws': re.compile(r'\b[a-z][a-z0-9-]*:[A-Z][A-Za-z0-9]+\b'),
    'gcp': re.compile(r'\b[a-z][a-z0-9]*\.[a-zA-Z0-9_]+\.[a-zA-Z0-9_]+\b'),
    'azure': re.compile(r'\b(?:Microsoft|microsoft)\.[a-zA-Z0-9]+/[a-zA-Z0-9_*/.-]+'),
}
GCP_ACTION = re.compile(r'^(?:get|list|set|create|update|delete|use|access|add|remove|run|sign|act|invoke|execute|download|upload|publish|receive|consume|attach|detach|enable|disable|destroy|restore|undelete|start|stop|connect|impersonate|approve|bind|escalate|read|write|mutate|insert|export|import|reset|renew|revoke|fetch|retrieve|generate|search|query|call|cancel|patch|replace|move|open|override|batch|edit|drain|join|test|resolve|manage|validate|assume|establish|force|commit|close|push|submit|claim|rotate|allocate|mount|watch)', re.I)
GRAPH_SCOPE = re.compile(r'\b[A-Z][A-Za-z0-9]*(?:\.[A-Za-z0-9]+)*\.(?:Read|ReadWrite|Write|Manage|FullControl)(?:\.[A-Za-z0-9]+)*\b')


def inventory(book_root: Path) -> list[dict[str, str]]:
    rows = {}
    for provider in PATTERNS:
        for path in sorted((book_root / f'{provider}-security').rglob('*.md')):
            for number, line in enumerate(path.read_text().splitlines(), 1):
                tokens = PATTERNS[provider].findall(line)
                if provider == 'azure':
                    tokens += GRAPH_SCOPE.findall(line)
                for permission in tokens:
                    permission = permission.rstrip('.')
                    if provider == 'azure' and permission.casefold().startswith('microsoft.com/'):
                        continue
                    if provider == 'gcp' and not GCP_ACTION.match(permission.rsplit('.', 1)[-1]):
                        continue
                    if '/' in permission and provider == 'azure' and not permission.casefold().endswith(('/read', '/write', '/delete', '/action', '/update', '/manage')):
                        continue
                    key = (provider, permission.casefold() if provider != 'gcp' else permission)
                    if key not in rows:
                        rows[key] = {
                            'provider': provider, 'permission': permission,
                            'severity': classify_permission(provider, permission, unknown_default='medium'),
                            'classification': 'not_a_permission' if is_non_permission(provider, permission) else 'explicit_override' if severity_override(provider, permission) else 'baseline_or_combination',
                            'source_locations': [],
                        }
                    location = str(path.relative_to(book_root)) + ':' + str(number)
                    rows[key]['source_locations'].append(location)
    for row in rows.values():
        row['source_locations'] = ';'.join(row['source_locations'])
    return [rows[key] for key in sorted(rows)]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--book-root', type=Path, required=True, help='src/pentesting-cloud in a clean book checkout')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not all((args.book_root / f'{p}-security').is_dir() for p in PATTERNS):
        parser.error('--book-root must contain aws-security, gcp-security and azure-security')
    rows = inventory(args.book_root)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open('w') as stream:
        writer = csv.DictWriter(stream, ['provider', 'permission', 'severity', 'classification', 'source_locations'], lineterminator='\n')
        writer.writeheader()
        writer.writerows(rows)
    print(dict(Counter(row['provider'] for row in rows)))


if __name__ == '__main__':
    main()
