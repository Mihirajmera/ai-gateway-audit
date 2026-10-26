from __future__ import annotations

import json
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest

from ai_gateway_audit.__main__ import EXAMPLES, main
from ai_gateway_audit.exceptions import ExceptionError, load

REPO = Path(__file__).resolve().parent.parent
FAKE_SECRETS = ('example-openai-key-not-real', 'sk-1234', 'example-db-password', 'example-ui-password')


def run_cli(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, '-m', 'ai_gateway_audit', *args], cwd=REPO,
                          capture_output=True, text=True, encoding='utf-8')


def test_demo_writes_every_output_and_leaks_no_secret(tmp_path):
    out = tmp_path / 'audit'
    assert main(['demo', '--out', str(out)]) == 0
    files = [p for p in out.rglob('*') if p.is_file()]
    assert {p.name for p in files} >= {'gateway-audit.md', 'findings.csv', 'assessment-results.json',
                                       'insecure.json', 'hardened.json'}
    for p in files:
        text = p.read_text(encoding='utf-8')
        assert not any(s in text for s in FAKE_SECRETS), p


def test_evidence_hash_and_source_hashes(tmp_path):
    out = tmp_path / 'audit'
    main(['demo', '--out', str(out)])
    record = json.loads((out / 'evidence' / 'insecure.json').read_text(encoding='utf-8'))
    from ai_gateway_audit.report import sha256
    assert record['sha256'] == sha256({'sources': record['sources'], 'inventory': record['inventory']})
    assert all(len(s['sha256']) == 64 for s in record['sources'])
    assert {r['status'] for r in record['results']} == {'FAIL'}


def test_output_is_reproducible(tmp_path, monkeypatch):
    monkeypatch.setenv('SOURCE_DATE_EPOCH', '1791763200')
    a, b = tmp_path / 'a', tmp_path / 'b'
    for out in (a, b):
        main(['scan', str(EXAMPLES), '--out', str(out), '--as-of', '2026-10-26'])
    for p in a.rglob('*'):
        if p.is_file():
            assert p.read_bytes() == (b / p.relative_to(a)).read_bytes(), p


def test_oscal_marks_failed_controls(tmp_path):
    out = tmp_path / 'audit'
    main(['scan', str(EXAMPLES / 'insecure'), '--out', str(out)])
    doc = json.loads((out / 'oscal' / 'assessment-results.json').read_text(encoding='utf-8'))
    states = {f['target']['target-id']: f['target']['status']['state']
              for f in doc['assessment-results']['results'][0]['findings']}
    assert states['ia-5.7'] == 'not-satisfied' and states['sc-23'] == 'not-satisfied'


def write_exceptions(tmp_path, expires: str, **extra) -> Path:
    entry = {'check': 'GWA-09', 'deployment': 'insecure', 'decision': 'risk-accepted',
             'reason': 'Internal proxy', 'approved_by': 'Head of Platform', 'expires': expires, **extra}
    lines = ['exceptions:', '  - ' + '\n    '.join(f'{k}: {v}' for k, v in entry.items())]
    p = tmp_path / 'exceptions.yaml'
    p.write_text('\n'.join(lines) + '\n', encoding='utf-8')
    return p


def test_valid_exception_covers_finding(tmp_path):
    exc = write_exceptions(tmp_path, '2027-01-31')
    proc = run_cli('scan', str(EXAMPLES / 'insecure'), '--out', str(tmp_path / 'o'), '--format', 'json',
                   '--exceptions', str(exc), '--as-of', '2026-10-26')
    gwa09 = json.loads(proc.stdout)['deployments'][0]['results']['GWA-09']
    assert gwa09['status'] == 'EXCEPTION'
    assert gwa09['findings'][0]['exception']['approved_by'] == 'Head of Platform'


def test_expired_exception_reopens_finding(tmp_path):
    exc = write_exceptions(tmp_path, '2026-09-30')
    proc = run_cli('scan', str(EXAMPLES / 'insecure'), '--out', str(tmp_path / 'o'), '--format', 'json',
                   '--exceptions', str(exc), '--as-of', '2026-10-26')
    doc = json.loads(proc.stdout)
    assert doc['deployments'][0]['results']['GWA-09']['status'] == 'FAIL'
    assert doc['expired_exceptions'][0]['check'] == 'GWA-09'
    assert 'Expired exceptions' in (tmp_path / 'o' / 'gateway-audit.md').read_text(encoding='utf-8')


@pytest.mark.parametrize('body,error', [
    ('exceptions:\n  - check: GWA-09\n    deployment: x\n', 'missing'),
    ('exceptions:\n  - {check: GWA-99, deployment: x, decision: risk-accepted, reason: r, approved_by: a, expires: 2027-01-01}\n', 'unknown check'),
    ('exceptions:\n  - {check: GWA-09, deployment: x, decision: ignore, reason: r, approved_by: a, expires: 2027-01-01}\n', 'decision'),
    ('exceptions:\n  - {check: GWA-09, deployment: x, decision: deferred, reason: r, approved_by: a, expires: soon}\n', 'YYYY-MM-DD'),
])
def test_invalid_exceptions_are_rejected(tmp_path, body, error):
    p = tmp_path / 'e.yaml'
    p.write_text(body, encoding='utf-8')
    with pytest.raises(ExceptionError, match=error):
        load(p)


def test_fail_on_gate(tmp_path):
    out = str(tmp_path / 'o')
    assert run_cli('scan', str(EXAMPLES / 'insecure'), '--out', out, '--fail-on', 'high').returncode == 1
    assert run_cli('scan', str(EXAMPLES / 'hardened'), '--out', out, '--fail-on', 'low').returncode == 0


def test_nothing_to_scan(tmp_path):
    assert main(['scan', str(tmp_path)]) == 2
