"""Exercise fetch failures and retries without accessing GitHub."""
import importlib.util
from pathlib import Path
import subprocess
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('permission_fetch', ROOT / 'scripts/fetch_hacktricks_permissions.py')
fetcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetcher)


def complete_checkout(arguments, deadline):
    if arguments[0] == 'clone':
        directory = Path(arguments[-1]) / 'src/permission-categorizations'
        directory.mkdir(parents=True)
        for provider in ('aws', 'gcp', 'azure', 'k8s'):
            (directory / f'{provider}.yaml').write_text(provider)


def test_success_after_timeout_then_network_failure(tmp_path, monkeypatch):
    calls = []
    def git(arguments, deadline):
        calls.append((arguments, deadline))
        if len(calls) == 1:
            raise subprocess.TimeoutExpired('git', 150)
        if len(calls) == 2:
            raise subprocess.CalledProcessError(128, 'git')
        complete_checkout(arguments, deadline)
    sleep = Mock()
    monkeypatch.setattr(fetcher, '_git', git)
    monkeypatch.setattr(fetcher.time, 'sleep', sleep)
    destination = tmp_path / 'source'
    fetcher.fetch(destination)
    assert (destination / 'src/permission-categorizations/k8s.yaml').read_text() == 'k8s'
    assert [call.args[0] for call in sleep.call_args_list] == [15, 30]
    assert not list(tmp_path.glob('.permission-fetch-*'))
    assert calls[2][1] == calls[3][1] == calls[4][1]  # One deadline for the whole attempt.


def test_exhausted_attempts_leave_no_partial_destination(tmp_path, monkeypatch):
    git = Mock(side_effect=subprocess.CalledProcessError(128, 'git'))
    sleep = Mock()
    monkeypatch.setattr(fetcher, '_git', git)
    monkeypatch.setattr(fetcher.time, 'sleep', sleep)
    with pytest.raises(RuntimeError, match='five attempts'):
        fetcher.fetch(tmp_path / 'source')
    assert git.call_count == 5
    assert [call.args[0] for call in sleep.call_args_list] == [15, 30, 60, 120]
    assert list(tmp_path.iterdir()) == []


def test_incomplete_checkout_is_retried(tmp_path, monkeypatch):
    git = Mock()
    monkeypatch.setattr(fetcher, '_git', git)
    monkeypatch.setattr(fetcher.time, 'sleep', Mock())
    with pytest.raises(RuntimeError, match='five attempts'):
        fetcher.fetch(tmp_path / 'source')
    assert git.call_count == 15
    assert not (tmp_path / 'source').exists()


def test_existing_destination_is_preserved(tmp_path):
    destination = tmp_path / 'source'
    destination.mkdir()
    marker = destination / 'existing'
    marker.write_text('keep')
    with pytest.raises(ValueError, match='existing destination'):
        fetcher.fetch(destination)
    assert marker.read_text() == 'keep'


def test_git_uses_deadline_and_disables_interactive_auth(monkeypatch):
    run = Mock()
    monkeypatch.setattr(fetcher.subprocess, 'run', run)
    monkeypatch.setattr(fetcher.time, 'monotonic', lambda: 100)
    fetcher._git(['fetch'], 125)
    assert run.call_args.kwargs['timeout'] == 25
    assert run.call_args.kwargs['env']['GIT_TERMINAL_PROMPT'] == '0'
    assert 'http.lowSpeedTime=30' in run.call_args.args[0]
    with pytest.raises(subprocess.TimeoutExpired):
        fetcher._git(['fetch'], 99)
    assert run.call_count == 1
