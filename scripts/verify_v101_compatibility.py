#!/usr/bin/env python3
"""Read-only historical-source and current evidence compatibility checks.

Never executes archived code or the legacy release runner; no network, sudo,
namespace, firewall, release, or Git mutation commands are used.
"""
import argparse
import ast
import hashlib
import json
from pathlib import Path
import subprocess
import sys

from v08_evidence_validator import validate_session

BASELINE = '15470fc9b1e44016565b9a08a2a5123e6ff133bb'
SESSION = 'evidence/v08_runs/audit_20261024T155756056355Z_384'
FAILED_SNAPSHOT = 'evidence/v08_runs/snapshot_b4FUqJXy/gateway_forward.nft.json'


def source_inventory(runner_source, read_blob, root):
    """Inspect the archived FILES literal, without importing archived Python."""
    tree = ast.parse(runner_source)
    assignments = [node for node in tree.body if isinstance(node, ast.Assign)
                   and any(isinstance(t, ast.Name) and t.id == 'FILES' for t in node.targets)]
    if len(assignments) != 1:
        raise ValueError('Expected exactly one archived FILES inventory')
    inventory = ast.literal_eval(assignments[0].value)
    if not isinstance(inventory, dict) or not inventory:
        raise ValueError('Empty/invalid archived source inventory')
    results = []
    for name, digest in inventory.items():
        relative = Path(name)
        if relative.is_absolute() or '..' in relative.parts:
            raise ValueError('Unsafe archived source path')
        archived = hashlib.sha256(read_blob(name)).hexdigest()
        if archived != digest:
            raise ValueError(f'Archived source SHA-256 mismatch: {name}')
        current = hashlib.sha256((root / name).read_bytes()).hexdigest()
        results.append({'path': name, 'historical_sha256': archived,
                        'historical_integrity': 'PASS', 'current_sha256': current,
                        'legacy_source_pin': 'PASS' if current == digest else 'FAIL',
                        'relationship': 'unchanged' if current == digest else 'changed_since_v1'})
    return results


def verify(root):
    def git(*args):
        return subprocess.check_output(['git', '-C', str(root), *args], stderr=subprocess.PIPE)

    tagged = git('rev-parse', 'v1.0.0^{commit}').decode().strip()
    if tagged != BASELINE:
        raise ValueError('v1.0.0 differs from the recorded V1.0 commit')
    if git('cat-file', '-t', 'v1.0.0').strip() != b'tag':
        raise ValueError('Expected an annotated V1.0 tag')
    def blob(name):
        return git('show', BASELINE + ':' + name)
    sources = source_inventory(blob('scripts/v08_finish_release.py'), blob, root)
    # Keep the known failed capture as failed history, and verify no alteration.
    snapshot = (root / FAILED_SNAPSHOT).read_bytes()
    if snapshot != blob(FAILED_SNAPSHOT) or snapshot != b'':
        raise ValueError('Historical failed snapshot changed')
    count = validate_session(root / SESSION,
                             json.loads((root / 'tests/v08_audit_plan.json').read_text()))
    return {'historical_tag': {'status': 'PASS', 'commit': tagged},
            'sources': sources,
            'historical_failed_snapshot': {'status': 'FAIL', 'preserved': True,
                                           'reason': 'zero-byte failed capture, not valid JSON'},
            'current_validator_saved_session': {'status': 'PASS', 'cases': count},
            'legacy_release_runner': {'status': 'NOT RUN',
                                      'reason': 'historical source/HEAD/branch-bound deployment tool'},
            'live_network_validation': 'NOT RUN'}


def main():
    cli = argparse.ArgumentParser(description=__doc__)
    cli.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    args = cli.parse_args()
    try:
        print(json.dumps(verify(args.root), indent=2))
    except (OSError, ValueError, TypeError, KeyError, subprocess.CalledProcessError) as exc:
        print(f'COMPATIBILITY_ERROR: {exc}', file=sys.stderr)
        return 1
    # Exit 0 means compatibility checks completed, not that failed history passed.
    return 0


if __name__ == '__main__':
    sys.exit(main())
