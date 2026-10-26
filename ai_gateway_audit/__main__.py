"""CLI.

  ai-gateway-audit demo                       audit the bundled insecure and hardened examples
  ai-gateway-audit scan <paths> [--out audit] [--exceptions exceptions.yaml] [--as-of YYYY-MM-DD]
                                [--fail-on high] [--format json]
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import date
from pathlib import Path

from . import __version__
from .checks import run_all
from .exceptions import ExceptionError, apply, load
from .model import SEVERITY_ORDER
from .parsers import discover
from .report import build_time, counts, open_findings, status, write_all

EXAMPLES = Path(__file__).parent / 'examples'


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog='ai-gateway-audit',
                                 description='Audit AI gateway (LiteLLM) configuration and produce evidence.')
    ap.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    sub = ap.add_subparsers(dest='cmd', required=True)
    scan = sub.add_parser('scan', help='audit LiteLLM configs, Compose files and .env files')
    scan.add_argument('paths', nargs='+', type=Path, help='files or folders to scan')
    scan.add_argument('--out', type=Path, default=Path('audit'), help='output folder (default: audit)')
    scan.add_argument('--exceptions', type=Path, help='reviewed exceptions file (see README)')
    scan.add_argument('--as-of', type=date.fromisoformat, default=date.today(),
                      help='audit date, used for exception expiry (default: today)')
    scan.add_argument('--fail-on', choices=['high', 'medium', 'low', 'never'], default='never',
                      help='exit 1 if any open finding is at or above this severity (for CI gates)')
    scan.add_argument('--format', choices=['json'], default=None,
                      help='print the results as one JSON document on stdout (files are still written)')
    demo = sub.add_parser('demo', help='audit the bundled insecure and hardened examples')
    demo.add_argument('--out', type=Path, default=Path('audit-demo'), help='output folder (default: audit-demo)')
    args = ap.parse_args(argv)

    if args.cmd == 'demo':                               # build_time honours SOURCE_DATE_EPOCH
        return run([EXAMPLES], args.out, build_time().date(), None, 'never', demo=True)

    missing = [p for p in args.paths if not p.exists()]
    if missing:
        ap.error(f'not found: {", ".join(map(str, missing))}')
    return run(args.paths, args.out, args.as_of, args.exceptions, args.fail_on, fmt=args.format)


def run(paths: list[Path], out: Path, as_of: date, exceptions_file: Path | None, fail_on: str,
        demo: bool = False, fmt: str | None = None) -> int:
    deployments = discover(paths)
    if not deployments:
        print('No LiteLLM config or LiteLLM Compose service found.', file=sys.stderr)
        return 2
    try:
        exceptions = load(exceptions_file) if exceptions_file else []
    except (ExceptionError, OSError) as exc:
        print(f'exceptions: {exc}', file=sys.stderr)
        return 2

    results = [(d, run_all(d)) for d in deployments]
    expired = apply([f for _, r in results for fs in r.values() if fs for f in fs], exceptions, as_of)
    written = write_all(results, out, as_of, expired)

    if fmt == 'json':
        json.dump({'as_of': as_of.isoformat(), 'deployments': [{
            'deployment': d.id,
            'sources': [s.path for s in d.sources],
            'results': {cid: {'status': status(fs), 'findings': [asdict(f) for f in fs or []]}
                        for cid, fs in sorted(r.items())},
        } for d, r in results], 'expired_exceptions': expired}, sys.stdout, indent=2)
        sys.stdout.write('\n')
        return _exit_code(results, fail_on)

    print(f'{"DEPLOYMENT":<28} {"HIGH":>5} {"MED":>5} {"LOW":>5} {"N/A":>5}')
    for d, r in results:
        c = counts([f for fs in r.values() if fs for f in fs if not f.exception])
        na = sum(1 for fs in r.values() if fs is None)
        print(f'{d.id[:28]:<28} {c["high"]:>5} {c["medium"]:>5} {c["low"]:>5} {na:>5}')
    if expired:
        print(f'\n{len(expired)} exception(s) have expired and no longer apply.')
    print(f'\nReport:   {written["report"]}\nFindings: {written["sheet"]}\nOSCAL:    {written["oscal"]}')
    if demo:
        print('\nThe insecure example fails on purpose; the hardened one shows what passing looks like.'
              '\nNext: run `ai-gateway-audit scan <folder with your config.yaml and compose file>`.')
    return _exit_code(results, fail_on)


def _exit_code(results, fail_on: str) -> int:
    if fail_on != 'never':
        floor = SEVERITY_ORDER[fail_on]
        if any(SEVERITY_ORDER[f.severity] >= floor for f in open_findings(results)):
            return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
