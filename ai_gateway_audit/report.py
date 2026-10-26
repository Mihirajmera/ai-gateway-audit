"""Audit outputs: a reviewer report (Markdown), a findings sheet (CSV), hashed per-deployment
evidence (JSON) and OSCAL assessment results."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import uuid
from collections import Counter
from dataclasses import asdict
from datetime import date, datetime, timezone
from pathlib import Path

from .checks import CONTROLS, MANUAL
from .model import SEVERITY_ORDER, Deployment, Finding

FRAMEWORK_LABELS = {'nist_800_53': 'NIST 800-53', 'soc2': 'SOC 2', 'owasp_llm': 'OWASP LLM'}

Result = tuple[Deployment, dict[str, list[Finding] | None]]


# --------------------------------------------------------------------------- helpers

def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), default=str)


def sha256(obj) -> str:
    return hashlib.sha256(canonical(obj).encode('utf-8')).hexdigest()


def build_time() -> datetime:
    """Now, or SOURCE_DATE_EPOCH when set (the reproducible-builds convention), so a rerun on the
    same inputs can produce byte-identical output."""
    epoch = os.environ.get('SOURCE_DATE_EPOCH')
    if epoch:
        return datetime.fromtimestamp(int(epoch), timezone.utc)
    return datetime.now(timezone.utc).replace(microsecond=0)


def status(findings: list[Finding] | None) -> str:
    if findings is None:
        return 'NOT ASSESSED'
    if not findings:
        return 'PASS'
    return 'EXCEPTION' if all(f.exception for f in findings) else 'FAIL'


def open_findings(results: list[Result]) -> list[Finding]:
    return [f for _, r in results for fs in r.values() if fs for f in fs if not f.exception]


def counts(findings: list[Finding]) -> Counter:
    return Counter(f.severity for f in findings)


def inventory(dep: Deployment) -> dict:
    return json.loads(canonical({
        'config': dep.config,
        'env': {k: {'literal': v.literal, 'value': v.value, 'source': v.source} for k, v in sorted(dep.env.items())},
        'images': [asdict(i) for i in dep.images],
        'plaintext_secrets': [{'setting': s, 'source': src} for s, src in dep.secrets],
    }))


def _cell(value) -> str:
    return str(value).replace('|', '\\|').replace('\n', ' ')


def _frameworks(check_id: str) -> str:
    c = CONTROLS[check_id]
    return '; '.join(f'{label} {", ".join(c[key])}' for key, label in FRAMEWORK_LABELS.items() if c.get(key))


def _oscal_id(control: str) -> str:
    return control.lower().replace('(', '.').replace(')', '')


# --------------------------------------------------------------------------- writers

def write_all(results: list[Result], out: Path, as_of: date, expired: list[dict],
              collected: datetime | None = None) -> dict[str, Path]:
    collected = collected or build_time()
    out.mkdir(parents=True, exist_ok=True)
    evidence = write_evidence(results, out / 'evidence', as_of, collected)
    return {
        'report': write_markdown(results, out / 'gateway-audit.md', as_of, evidence, expired),
        'sheet': write_csv(results, out / 'findings.csv'),
        'oscal': write_oscal(results, out / 'oscal' / 'assessment-results.json', as_of, collected, evidence),
        **{f'evidence:{k}': v[0] for k, v in evidence.items()},
    }


def write_evidence(results: list[Result], folder: Path, as_of: date, collected: datetime) -> dict[str, tuple[Path, str]]:
    """One file per deployment. The hash covers the source file hashes and the redacted
    inventory, so any later edit to what was found is detectable."""
    folder.mkdir(parents=True, exist_ok=True)
    index = {}
    for dep, res in results:
        hashed = {'sources': [asdict(s) for s in dep.sources], 'inventory': inventory(dep)}
        record = {
            'deployment_id': dep.id,
            'folder': dep.folder,
            'collected': collected.isoformat(),
            'audit_as_of': as_of.isoformat(),
            **hashed,
            'results': [{
                'check_id': cid,
                'title': CONTROLS[cid]['title'],
                'status': status(fs),
                'findings': [asdict(f) for f in fs or []],
            } for cid, fs in sorted(res.items())],
            'sha256': sha256(hashed),
            'hash_scope': 'sha256 of canonical JSON (sorted keys, no spaces) of {sources, inventory}',
        }
        path = folder / f'{dep.id}.json'
        path.write_text(json.dumps(record, indent=2, sort_keys=True, default=str) + '\n',
                        encoding='utf-8', newline='\n')
        index[dep.id] = (path, record['sha256'])
    return index


def write_csv(results: list[Result], path: Path) -> Path:
    with path.open('w', newline='', encoding='utf-8') as fh:
        w = csv.writer(fh, lineterminator='\n')         # same bytes on every OS
        w.writerow(['deployment', 'check_id', 'control', 'severity', 'setting', 'finding', 'recommendation',
                    'exception_decision', 'exception_expires', 'owner', 'remediation_due', 'status'])
        for dep, res in results:
            for cid, fs in sorted(res.items()):
                for f in fs or []:
                    e = f.exception or {}
                    w.writerow([dep.id, cid, CONTROLS[cid]['title'], f.severity, f.setting or '', f.message,
                                f.recommendation, e.get('decision', ''), e.get('expires', ''), '', '',
                                'excepted' if e else 'open'])
    return path


def write_markdown(results: list[Result], path: Path, as_of: date, evidence: dict, expired: list[dict]) -> Path:
    found = open_findings(results)
    c = counts(found)
    excepted = sum(1 for _, r in results for fs in r.values() if fs for f in fs if f.exception)
    L = [f'# AI Gateway Audit: {as_of.isoformat()}', '',
         f'**{len(results)} gateway deployment{"s" if len(results) != 1 else ""}**, '
         f'**{len(found)} open findings** ({c["high"]} high, {c["medium"]} medium, {c["low"]} low)'
         f'{f", {excepted} covered by reviewed exceptions" if excepted else ""}.', '',
         '| Deployment | Sources | High | Medium | Low | Not assessed |', '|---|---|---:|---:|---:|---:|']
    for dep, res in results:
        dc = counts([f for fs in res.values() if fs for f in fs if not f.exception])
        na = sum(1 for fs in res.values() if fs is None)
        L.append(f'| [{_cell(dep.id)}](#{dep.id}) | {", ".join(f"`{_cell(s.path)}`" for s in dep.sources)} | '
                 f'{dc["high"]} | {dc["medium"]} | {dc["low"]} | {na} |')

    L += ['', '## Control results', '', '| Check | Control | ' + ' | '.join(_cell(d.id) for d, _ in results)
          + ' | Frameworks |', '|---|---|' + '---|' * len(results) + '---|']
    for cid in sorted(CONTROLS):
        L.append(f'| {cid} | {CONTROLS[cid]["title"]} | '
                 + ' | '.join(status(r.get(cid)) for _, r in results) + f' | {_frameworks(cid)} |')

    if expired:
        L += ['', '## Expired exceptions', '', 'These matched a finding but are past their expiry date, so the '
              'finding is open again:', '', '| Check | Deployment | Decision | Approved by | Expired |',
              '|---|---|---|---|---|']
        L += [f'| {e["check"]} | {_cell(e["deployment"])} | {e["decision"]} | {_cell(e["approved_by"])} | '
              f'{e["expires"]} |' for e in expired]

    for dep, res in results:
        L += ['', '---', '', f'<a id="{dep.id}"></a>', f'## {_cell(dep.id)}', '',
              f'- **Folder:** `{_cell(dep.folder)}`',
              f'- **Evidence:** `evidence/{dep.id}.json` (sha256 `{evidence[dep.id][1][:16]}…`)',
              '- **Sources read:**']
        L += [f'  - `{_cell(s.path)}` ({s.type}, sha256 `{s.sha256[:16]}…`)' for s in dep.sources]
        items = sorted(((cid, f) for cid, fs in res.items() for f in fs or []),
                       key=lambda x: (bool(x[1].exception), -SEVERITY_ORDER[x[1].severity], x[0]))
        L += ['', '### Findings', '']
        if items:
            L += ['| Check | Severity | Finding | Recommendation | Status |', '|---|---|---|---|---|']
            for cid, f in items:
                st = (f'{f.exception["decision"]} until {f.exception["expires"]} ({_cell(f.exception["approved_by"])})'
                      if f.exception else '**open**')
                L.append(f'| {cid} | {f.severity} | {_cell(f.message)} | {_cell(f.recommendation)} | {st} |')
        else:
            L.append('No findings.')
        na = [cid for cid, fs in res.items() if fs is None]
        if na:
            L += ['', '### Not assessed', '', 'No file describing how this gateway is deployed (Docker Compose or '
                  '.env) was found, so these checks could not be evaluated. Scan the deployment files too:', '']
            L += [f'- {cid}: {CONTROLS[cid]["title"]}' for cid in sorted(na)]

    L += ['', '## Needs evidence from outside the configuration', '',
          'A configuration file can\'t prove these. Collect evidence for them separately:', '']
    L += [f'- **{m["id"]}:** {m["title"]} (NIST 800-53 {", ".join(m["nist_800_53"])})' for m in MANUAL]
    L += ['', '## Sign-off', '', 'I have reviewed the findings above and the decisions recorded for each.', '',
          '| Role | Name | Date |', '|---|---|---|', '| Gateway owner | | |', '| Reviewer | | |']
    path.write_text('\n'.join(L) + '\n', encoding='utf-8', newline='\n')
    return path


def _uid(*parts) -> str:
    """Deterministic UUID: the same audit at the same time always gets the same IDs."""
    return str(uuid.uuid5(uuid.NAMESPACE_URL, 'ai-gateway-audit:' + '/'.join(map(str, parts))))


def write_oscal(results: list[Result], path: Path, as_of: date, collected: datetime, evidence: dict) -> Path:
    """OSCAL 1.1.2 assessment-results: one observation per deployment, one finding per NIST
    800-53 control the assessed checks map to. Excepted findings don't make a control
    not-satisfied, but the exception is named in the finding's remarks."""
    path.parent.mkdir(parents=True, exist_ok=True)
    now = collected.isoformat()
    observations, obs_by_dep = [], {}
    for dep, res in results:
        oid = _uid(now, 'observation', dep.id)
        obs_by_dep[dep.id] = oid
        ev_path, digest = evidence[dep.id]
        found = [f for fs in res.values() if fs for f in fs]
        observations.append({
            'uuid': oid,
            'title': f'Configuration audit of {dep.id}',
            'description': f'{len(dep.sources)} files read, {len(found)} findings.',
            'methods': ['EXAMINE'],
            'types': ['finding' if found else 'control-objective'],
            'subjects': [{'subject-uuid': str(uuid.uuid5(uuid.NAMESPACE_URL, 'ai-gateway:' + dep.folder)),
                          'type': 'component', 'title': dep.id}],
            'relevant-evidence': [{'href': f'../evidence/{ev_path.name}', 'description': 'Hashed gateway inventory',
                                   'props': [{'name': 'sha256', 'value': digest}]}],
            'collected': now,
        })

    by_control: dict[str, list[str]] = {}
    for cid in sorted(CONTROLS):
        for ctl in CONTROLS[cid]['nist_800_53']:
            by_control.setdefault(ctl, []).append(cid)
    oscal_findings = []
    for ctl, check_ids in sorted(by_control.items()):
        assessed = [d.id for d, r in results if any(r[c] is not None for c in check_ids)]
        if not assessed:
            continue
        failing = [d.id for d, r in results if any(f for c in check_ids for f in r[c] or [] if not f.exception)]
        excepted = sorted({f'{f.check_id} {f.exception["decision"]} until {f.exception["expires"]}'
                           for _, r in results for c in check_ids for f in r[c] or [] if f.exception})
        finding = {
            'uuid': _uid(now, 'finding', ctl),
            'title': f'{ctl}: {", ".join(check_ids)}',
            'description': '; '.join(CONTROLS[c]['title'] for c in check_ids),
            'target': {'type': 'objective-id', 'target-id': _oscal_id(ctl),
                       'status': {'state': 'not-satisfied' if failing else 'satisfied'}},
            'related-observations': [{'observation-uuid': obs_by_dep[d]} for d in (failing or assessed)],
        }
        if excepted:
            finding['remarks'] = 'Reviewed exceptions: ' + '; '.join(excepted)
        oscal_findings.append(finding)

    doc = {'assessment-results': {
        'uuid': _uid(now, 'assessment-results'),
        'metadata': {'title': 'AI gateway configuration audit', 'last-modified': now,
                     'version': as_of.isoformat(), 'oscal-version': '1.1.2'},
        'import-ap': {'href': '#'},
        'results': [{
            'uuid': _uid(now, 'result'),
            'title': f'AI gateway audit as of {as_of.isoformat()}',
            'description': 'Automated review of AI gateway configuration against tier-0 infrastructure controls.',
            'start': now, 'end': now,
            'reviewed-controls': {'control-selections': [
                {'include-controls': [{'control-id': _oscal_id(c)} for c in sorted(by_control)]}]},
            'observations': observations,
            'findings': oscal_findings,
        }],
    }}
    path.write_text(json.dumps(doc, indent=2) + '\n', encoding='utf-8', newline='\n')
    return path
