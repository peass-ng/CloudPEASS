"""Contract tests for offline canonical data consumption and safe synchronization."""
import hashlib
import importlib.util
import json
from pathlib import Path
import sys

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
CLOUD = (ROOT / 'src/CloudPEASS').is_dir()
RULES = ROOT / ('src/CloudPEASS/risk_rules' if CLOUD else 'risk_rules')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


syncer = load('canonical_sync', ROOT / 'scripts/sync_hacktricks_permissions.py')
engine = load('canonical_engine', ROOT / ('src/CloudPEASS/permission_risk_classifier.py' if CLOUD else 'scripts/cloud_permission_risks.py'))


@pytest.mark.parametrize('provider', syncer.PROVIDERS)
def test_bundled_schema_and_hash(provider):
    path = RULES / f'{provider}.yaml'
    syncer.validate(yaml.safe_load(path.read_text()), provider)
    manifest = json.loads((RULES / 'hacktricks-source.json').read_text())
    assert manifest['sha256'][path.name] == hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.parametrize('provider', syncer.PROVIDERS[:3])
def test_catalog_and_combinations_are_consumed(provider):
    data = engine._load_yaml(provider)
    for severity, permissions in data['permission_categories'].items():
        for permission in permissions:
            assert engine.classify_permission(provider, permission, unknown_default='medium') == severity, permission
    assert engine.load_criticality_combinations(provider) == {
        level: tuple(tuple(combo) for combo in data['combinations'][level])
        for level in ('critical', 'high')}


def test_kubernetes_rules_drive_runtime(monkeypatch):
    if CLOUD:
        import types
        package = types.ModuleType('canonical_k8s_package')
        package.__path__ = [str(ROOT / 'src/k8s')]
        sys.modules[package.__name__] = package
        models = load('canonical_k8s_package.models', ROOT / 'src/k8s/models.py')
        risks = load('canonical_k8s_package.risks', ROOT / 'src/k8s/risks.py')
        PermissionKey = models.PermissionKey
    else:
        risks = load('canonical_k8s', ROOT / 'bluepeass/k8s_risks.py')
        PermissionKey = risks.PermissionKey
    original = risks._rules()
    monkeypatch.setattr(risks, '_rules', lambda: ({'match': {'field': 'namespace', 'op': 'eq', 'value': 'restricted'},
                                               'severity': 'low', 'description': 'Scoped {full}'},) + original)
    assert risks.classify_permission(PermissionKey('get', resource='secrets', namespace='restricted')) == ('low', 'Scoped secrets')
    assert risks.classify_permission(PermissionKey('get', resource='secrets'))[0] == 'high'


def test_sync_checks_all_inputs_before_writing(tmp_path):
    book = tmp_path / 'book'
    source = book / 'src/permission-categorizations'
    source.mkdir(parents=True)
    for provider in syncer.PROVIDERS:
        (source / f'{provider}.yaml').write_bytes((RULES / f'{provider}.yaml').read_bytes())
    (source / 'k8s.yaml').write_text('version: 99\nprovider: k8s\n')
    with pytest.raises(ValueError, match='Unsupported k8s'):
        syncer.sync(book, tmp_path / 'target')
    assert not (tmp_path / 'target').exists()


def test_sync_ignores_unrelated_source_revision(tmp_path):
    book = tmp_path / 'book'
    source = book / 'src/permission-categorizations'
    source.mkdir(parents=True)
    for provider in syncer.PROVIDERS:
        (source / f'{provider}.yaml').write_bytes((RULES / f'{provider}.yaml').read_bytes())
    # This fixture is deliberately not a git checkout: unchanged hashes must
    # avoid consulting a newer source revision, and --check must write nothing.
    syncer.sync(book, ROOT, check=True)


def test_rejects_conflicting_case_aliases():
    data = dict(version=1, provider='aws', permission_categories={
        'low': ['example:Read'], 'medium': [], 'high': ['EXAMPLE:READ'], 'critical': []},
        combinations={'critical': [], 'high': []})
    with pytest.raises(ValueError, match='Duplicate'):
        syncer.validate(data, 'aws')


def test_rejects_executable_match_and_template_fields():
    for match in ({'field': '__import__', 'op': 'eq', 'value': 'os'}, {'eval': 'anything'}):
        with pytest.raises(ValueError):
            syncer.validate_match(match)
    data = dict(version=1, provider='k8s', rules=[dict(id='fallback', match={'always': True},
                severity='low', description='{resource.__class__}')])
    with pytest.raises(ValueError, match='placeholder'):
        syncer.validate(data, 'k8s')


@pytest.mark.parametrize('cloud_target', (True, False))
def test_changed_source_updates_copies_and_generated_lists(tmp_path, monkeypatch, cloud_target):
    book = tmp_path / 'book'
    source = book / 'src/permission-categorizations'
    source.mkdir(parents=True)
    for provider in syncer.PROVIDERS[:3]:
        data = dict(version=1, provider=provider,
                    permission_categories={level: [] for level in syncer.LEVELS},
                    combinations={'critical': [], 'high': []})
        (source / f'{provider}.yaml').write_text(yaml.safe_dump(data, sort_keys=False))
    (source / 'k8s.yaml').write_text(yaml.safe_dump(dict(version=1, provider='k8s', rules=[
        dict(id='fallback', match={'always': True}, severity='low', description='Discovery')]), sort_keys=False))
    target = tmp_path / 'target'
    engine_path = target / ('src/CloudPEASS/permission_risk_classifier.py' if cloud_target else 'scripts/cloud_permission_risks.py')
    engine_path.parent.mkdir(parents=True)
    engine_path.touch()
    if cloud_target:
        folder = target / 'src/sensitive_permissions'
        folder.mkdir(parents=True)
        for provider in syncer.PROVIDERS[:3]:
            (folder / f'{provider}.py').write_text('very_sensitive_combinations = []\nsensitive_combinations = []\n')
    monkeypatch.setattr(syncer.subprocess, 'check_output', lambda *args, **kwargs: 'a' * 40)
    syncer.sync(book, target)
    rules = target / ('src/CloudPEASS/risk_rules' if cloud_target else 'risk_rules')
    before = json.loads((rules / 'hacktricks-source.json').read_text())
    data = yaml.safe_load((source / 'aws.yaml').read_text())
    data['permission_categories']['critical'] = ['example:Grant']
    data['combinations']['critical'] = [['example:Grant']]
    (source / 'aws.yaml').write_text(yaml.safe_dump(data, sort_keys=False))
    monkeypatch.setattr(syncer.subprocess, 'check_output', lambda *args, **kwargs: 'b' * 40)
    syncer.sync(book, target)
    after = json.loads((rules / 'hacktricks-source.json').read_text())
    assert before['sha256']['aws.yaml'] != after['sha256']['aws.yaml']
    assert after['revision'] == 'b' * 40
    assert (rules / 'aws.yaml').read_bytes() == (source / 'aws.yaml').read_bytes()
    if cloud_target:
        import ast
        module = ast.parse((target / 'src/sensitive_permissions/aws.py').read_text())
        assert ast.literal_eval(module.body[0].value) == [['example:Grant']]
    else:
        assert yaml.safe_load((target / 'aws_permissions_cat.yaml').read_text())['critical'] == ['example:Grant']
    syncer.sync(book, target, check=True)
