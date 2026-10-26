"""Reviewed exceptions. A finding can be accepted only by a recorded decision with a reason, an
approver and an expiry date. Expired exceptions stop applying, so "accepted for now" can't
quietly become permanent.

exceptions.yaml:

  exceptions:
    - check: GWA-09
      deployment: gateway          # or "*" for every deployment
      setting: NO_DOCS             # optional: only findings about this setting
      decision: risk-accepted      # risk-accepted | not-applicable | deferred
      reason: Internal-only proxy behind the VPN; docs are used by the platform team.
      approved_by: Head of Platform
      expires: 2027-01-31
"""
from __future__ import annotations

from datetime import date
from pathlib import Path

import yaml

from .checks import CONTROLS
from .model import Finding

DECISIONS = {'risk-accepted', 'not-applicable', 'deferred'}
REQUIRED = ('check', 'deployment', 'decision', 'reason', 'approved_by', 'expires')


class ExceptionError(ValueError):
    pass


def load(path: Path) -> list[dict]:
    data = yaml.safe_load(path.read_text(encoding='utf-8')) or {}
    items = data.get('exceptions') if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise ExceptionError(f'{path}: expected a top-level "exceptions:" list')
    out = []
    for i, e in enumerate(items, 1):
        if not isinstance(e, dict):
            raise ExceptionError(f'{path}: exception {i} is not a mapping')
        missing = [k for k in REQUIRED if not e.get(k)]
        if missing:
            raise ExceptionError(f'{path}: exception {i} is missing {", ".join(missing)}')
        if e['check'] not in CONTROLS:
            raise ExceptionError(f'{path}: exception {i} names unknown check {e["check"]}')
        if e['decision'] not in DECISIONS:
            raise ExceptionError(f'{path}: exception {i} decision must be one of {", ".join(sorted(DECISIONS))}')
        expires = e['expires']
        if not isinstance(expires, date):
            try:
                expires = date.fromisoformat(str(expires))
            except ValueError:
                raise ExceptionError(f'{path}: exception {i} expires is not a YYYY-MM-DD date') from None
        out.append({**{k: str(e[k]) for k in REQUIRED if k != 'expires'},
                    'setting': str(e['setting']) if e.get('setting') else None,
                    'expires': expires.isoformat()})
    return out


def _matches(e: dict, f: Finding) -> bool:
    return (e['check'] == f.check_id and e['deployment'] in ('*', f.deployment_id)
            and (e['setting'] is None or e['setting'] == f.setting))


def apply(findings: list[Finding], exceptions: list[dict], as_of: date) -> list[dict]:
    """Attach each finding's covering exception, if one is valid on as_of. Returns the
    exceptions that matched a finding but had expired, so the report can name them."""
    expired = []
    for f in findings:
        for e in exceptions:
            if not _matches(e, f):
                continue
            if date.fromisoformat(e['expires']) >= as_of:
                f.exception = e
                break
            if e not in expired:
                expired.append(e)
    return expired
