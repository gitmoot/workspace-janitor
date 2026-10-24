#!/usr/bin/env python3
"""Real executable, isolated filesystem observations; no production policy."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument('binary', type=Path)
p.add_argument('receipt', type=Path)
a = p.parse_args()
binary = str(a.binary.resolve())
result = {'binary_sha256': hashlib.sha256(Path(binary).read_bytes()).hexdigest(), 'production_mutation': False}
with tempfile.TemporaryDirectory(prefix='janitor-report70-') as temporary:
    home = Path(temporary)
    root = home / 'inventory'
    project = root / 'project'
    (project / 'nested').mkdir(parents=True)
    payload = project / 'nested' / 'payload'
    payload.write_bytes(b'abcd')
    policy = home / 'policy.yaml'
    env = {k: v for k, v in os.environ.items() if not k.startswith(('JANITOR_', 'XDG_'))}
    env['HOME'] = str(home)
    def configure(depth=1, deep_limit=64):
        policy.write_text(f'''roots:
  - path: {root}
    max_depth: {depth}
collectors:
  git: false
  processes: false
  services: false
limits:
  deep_size_max_depth: {deep_limit}
caches:
  - name: report-only-fixture
    path: {project}
    action: quarantine
    retention: 30d
    max_bytes: 8192
''')
    def run(*args, human=False):
        command = [binary, '--policy', str(policy)]
        if not human:
            command += ['--format', 'json']
        command += list(args)
        done = subprocess.run(command, env=env, text=True, capture_output=True, timeout=30)
        if done.returncode:
            raise RuntimeError(f'{args}: {done.returncode}: {done.stderr[-3000:]}')
        return done.stdout if human else json.loads(done.stdout)
    def inventory():
        return run('status')['data']['inventory_report']
    configure()
    first = run('scan', '--deep-size')['data']['scan']['id']
    with payload.open('ab') as out:
        out.write(b'1234567')
    run('scan')
    latest = run('scan', '--deep-size')['data']['scan']['id']
    run('scan')
    report = inventory()
    assert report['growth']['scan_id'] == latest
    assert report['growth']['previous_scan_id'] == first
    row = next(row for row in report['growth']['changes'] if row['path'] == str(project))
    assert row['change_apparent_bytes'] == 7, row
    budget = next(row for row in report['store_budgets'] if row['path'] == str(project))
    assert budget['logical_threshold_bytes'] == 8192
    assert budget['allocated_prune_cap_bytes'] is None
    assert budget['decision_owner'] == 'unassigned'
    result['comparable_growth'] = report
    result['human_status'] = run('status', human=True)
    configure(depth=2)
    changed = inventory()['growth']
    assert changed['status'] == 'configured_scope_mismatch'
    assert all(row['change_apparent_bytes'] is None for row in changed['changes'])
    result['changed_scope'] = changed
    configure(deep_limit=1)
    run('scan', '--deep-size')
    run('scan', '--deep-size')
    incomplete = inventory()['growth']
    row = next(row for row in incomplete['changes'] if row['path'] == str(project))
    assert row['change_apparent_bytes'] is None and row['reason'] == 'measurement_incomplete_or_shallow', row
    result['incomplete'] = incomplete
    configure()
    run('scan', '--deep-size')
    project.rename(home / 'retained-old-project')
    (project / 'nested').mkdir(parents=True)
    payload.write_bytes(b'new generation' * 100)
    run('scan', '--deep-size')
    replaced = inventory()['growth']
    row = next(row for row in replaced['changes'] if row['path'] == str(project))
    assert row['change_apparent_bytes'] is None and row['reason'] == 'filesystem_identity_or_kind_changed', row
    result['replaced_identity'] = replaced
    result['daily_report'] = run('cycle')
    assert result['daily_report']['inventory_report']['growth']['scan_id']
    result['history'] = run('history')['data']['inventory_report']
    assert result['history']['growth']['scan_id']
a.receipt.write_text(json.dumps(result, indent=2) + '\n')
print(json.dumps({'receipt': str(a.receipt), 'binary_sha256': result['binary_sha256'], 'growth_bytes': 7, 'incomplete_and_changed_scope_unknown': True, 'replaced_identity_unknown': True, 'production_mutation': False}))
