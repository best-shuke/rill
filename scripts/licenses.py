#!/usr/bin/env python3
"""Write the license notices of everything the `rill` binary links, from the locked sources.

Usage: licenses.py OUTPUT [TARGET-TRIPLE]

Walks the non-dev dependency graph of rill-app for the target (default: the host) and
copies each package's top-level LICENSE / LICENCE / COPYING / NOTICE files, plus the
licenses of C libraries a crate vendors under deps/ (BoringSSL in boring-sys). Workspace
crates are rill's own (LICENSE, NOTICE) except the vendored ones that carry a license file.
Run after `cargo fetch --locked`; it reads the sources offline.
"""
import json
import os
from pathlib import Path
import subprocess
import sys

NAMES = ('LICENSE', 'LICENCE', 'COPYING', 'NOTICE')

target = sys.argv[2] if len(sys.argv) > 2 else next(
    line.split(': ', 1)[1] for line in subprocess.check_output(['rustc', '-vV'], text=True).splitlines()
    if line.startswith('host: '))
metadata = json.loads(subprocess.check_output([
    'cargo', 'metadata', '--format-version', '1', '--locked', '--offline',
    '--filter-platform', target,
    *(['--features', os.environ['RILL_FEATURES']] if os.environ.get('RILL_FEATURES') else [])
]))
nodes = {node['id']: node for node in metadata['resolve']['nodes']}
members = set(metadata['workspace_members'])
[root] = [p['id'] for p in metadata['packages'] if p['name'] == 'rill-app' and p['id'] in members]
visited = set()
pending = [root]
while pending:
    package = pending.pop()
    if package in visited:
        continue
    visited.add(package)
    for dep in nodes[package]['deps']:
        if any(kind['kind'] != 'dev' for kind in dep['dep_kinds']):
            pending.append(dep['pkg'])


def license_files(directory):
    found = [path for path in directory.iterdir()
             if path.is_file() and path.name.upper().startswith(NAMES)]
    vendored = directory / 'deps'
    if vendored.is_dir():
        for library in sorted(vendored.iterdir()):
            if library.is_dir():
                found += [path for path in library.iterdir()
                          if path.is_file() and path.name.upper().startswith(NAMES)]
    return sorted(found)


parts = ['rill: notices of the third-party code it is built from\n',
         '\nrill itself is MIT-licensed; see LICENSE and NOTICE beside this file.\n']
# A text many packages share verbatim is written once and referred back to.
first_seen = {}
for package in sorted(metadata['packages'], key=lambda p: (p['name'], p['version'])):
    if package['id'] not in visited:
        continue
    directory = Path(package['manifest_path']).parent
    files = license_files(directory)
    if package['id'] in members and not files:
        continue
    parts += [f"\n{'=' * 72}\n{package['name']} {package['version']}\n",
              f"Repository: {package.get('repository') or ''}\nLicense: {package.get('license') or ''}\n"]
    for path in files:
        text = path.read_text(encoding='utf-8', errors='replace')
        label = f"{package['name']} {package['version']} {path.relative_to(directory)}"
        if text in first_seen:
            parts.append(f'\n--- {path.relative_to(directory)}: same text as {first_seen[text]} ---\n')
            continue
        first_seen[text] = label
        parts += [f'\n--- {path.relative_to(directory)} ---\n', text, '\n']
Path(sys.argv[1]).write_text(''.join(parts), encoding='utf-8')
