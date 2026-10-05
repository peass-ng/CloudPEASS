#!/usr/bin/env python3
"""Fetch one consistent revision of HackTricks permission data with bounded retries."""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import tempfile
import time

SOURCE_URL = 'https://github.com/HackTricks-wiki/hacktricks-cloud.git'
ATTEMPTS = 5
ATTEMPT_TIMEOUT = 150
BACKOFF_SECONDS = (15, 30, 60, 120)


def _git(arguments, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise subprocess.TimeoutExpired(['git', *arguments], ATTEMPT_TIMEOUT)
    return subprocess.run(
        ['git', '-c', 'http.lowSpeedLimit=1024', '-c', 'http.lowSpeedTime=30', *arguments],
        check=True, timeout=remaining, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, env={**os.environ, 'GIT_TERMINAL_PROMPT': '0'},
    )


def fetch(destination: Path):
    destination = destination.resolve()
    if destination.exists():
        raise ValueError(f'Refusing to replace an existing destination: {destination}')
    destination.parent.mkdir(parents=True, exist_ok=True)
    for attempt in range(ATTEMPTS):
        print(f'Fetching canonical permissions: attempt {attempt + 1}/{ATTEMPTS}', flush=True)
        try:
            with tempfile.TemporaryDirectory(prefix='.permission-fetch-', dir=destination.parent) as folder:
                checkout = Path(folder) / 'checkout'
                deadline = time.monotonic() + ATTEMPT_TIMEOUT
                _git(['clone', '--depth=1', '--single-branch', '--branch=master',
                      '--filter=blob:none', '--no-checkout', SOURCE_URL, str(checkout)], deadline)
                _git(['-C', str(checkout), 'sparse-checkout', 'set', '--cone',
                      'src/permission-categorizations'], deadline)
                _git(['-C', str(checkout), 'checkout', '--force', 'HEAD'], deadline)
                for provider in ('aws', 'gcp', 'azure', 'k8s'):
                    if not (checkout / 'src/permission-categorizations' / f'{provider}.yaml').is_file():
                        raise RuntimeError(f'Missing canonical file: {provider}.yaml')
                checkout.rename(destination)
            return
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, RuntimeError) as error:
            print(f'Fetch attempt {attempt + 1} failed: {error}', flush=True)
            if attempt == ATTEMPTS - 1:
                raise RuntimeError('Unable to fetch canonical permissions after five attempts') from error
            delay = BACKOFF_SECONDS[attempt]
            print(f'Retrying in {delay} seconds', flush=True)
            time.sleep(delay)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--destination', type=Path, default=Path('.canonical-source'))
    args = parser.parse_args()
    fetch(args.destination)


if __name__ == '__main__':
    main()
