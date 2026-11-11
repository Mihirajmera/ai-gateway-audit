"""Gateway checks. Each function takes one deployment and returns findings; an empty list
means the control is satisfied. A check whose input isn't present (for example, no Compose
file to show which image runs) is reported as NOT ASSESSED rather than passed."""
from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

import yaml

from .model import REDACTED, Deployment, Finding

_CATALOG = yaml.safe_load((Path(__file__).parent / 'controls.yaml').read_text(encoding='utf-8'))
CONTROLS = _CATALOG['controls']
MANUAL = _CATALOG['manual']
ADVISORIES = yaml.safe_load((Path(__file__).parent / 'advisories.yaml').read_text(encoding='utf-8'))

# Tags that move. LiteLLM's October 2026 compromise repointed latest, main-latest and main-stable.
MUTABLE_TAGS = {'latest', 'main', 'main-latest', 'main-stable', 'stable', 'dev', 'nightly'}
# Callbacks that record counts and latency, not message content.
METRICS_ONLY_CALLBACKS = {'prometheus'}
# Settings that are reported by their own check, not as a generic plain-text secret.
MASTER_KEY_SETTINGS = {'general_settings.master_key', 'LITELLM_MASTER_KEY'}
UI_SECRET_SETTINGS = {'UI_PASSWORD'}

CheckFn = Callable[[Deployment], list[Finding]]
REGISTRY: dict[str, CheckFn] = {}


def check(check_id: str):
    def register(fn: CheckFn) -> CheckFn:
        REGISTRY[check_id] = fn
        return fn
    return register


def assessable(check_id: str, dep: Deployment) -> bool:
    needs = CONTROLS[check_id]['needs']
    if needs == 'config':
        return dep.config_found
    if check_id == 'GWA-07':
        return dep.deployment_found and bool(dep.images)
    if check_id == 'GWA-11':                 # only an image tag says which LiteLLM release runs
        return dep.deployment_found and any(litellm_version(img.ref) for img in dep.images)
    return dep.deployment_found


def run_all(dep: Deployment) -> dict[str, list[Finding] | None]:
    """check_id -> findings, or None when the check couldn't be assessed."""
    return {cid: (REGISTRY[cid](dep) if assessable(cid, dep) else None) for cid in sorted(REGISTRY)}


def truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in ('true', '1', 'yes', 'on')


def falsy(value) -> bool:
    """Explicitly turned off. Missing (None) is not falsy here."""
    if isinstance(value, bool):
        return not value
    return value is not None and str(value).strip().lower() in ('false', '0', 'no', 'off')


def _list(value) -> list[str]:
    if value is None:
        return []
    return [str(v) for v in (value if isinstance(value, list) else [value])]


def _env(dep: Deployment, name: str):
    v = dep.env.get(name)
    return v.value if v else None


@check('GWA-01')
def plaintext_credentials(dep: Deployment) -> list[Finding]:
    out = []
    for setting, source in dep.secrets:
        if setting in MASTER_KEY_SETTINGS or setting in UI_SECRET_SETTINGS:
            continue
        out.append(Finding('GWA-01', 'high', dep.id,
                           f'`{setting}` in `{source}` is a credential written in plain text.',
                           'Reference it with os.environ/NAME (or ${NAME} in Compose) and load it from a '
                           'secret manager. Rotate it: anyone who can read this file has had it.',
                           setting=setting))
    return out


@check('GWA-02')
def master_key(dep: Deployment) -> list[Finding]:
    configured = dep.general().get('master_key')
    env = dep.env.get('LITELLM_MASTER_KEY')
    out = []
    if configured == REDACTED:
        out.append(Finding('GWA-02', 'high', dep.id,
                           'The master key is written in plain text in the LiteLLM config. It grants admin '
                           'access to every model, key and budget on the proxy.',
                           'Set master_key: os.environ/LITELLM_MASTER_KEY and rotate the key.',
                           setting='general_settings.master_key'))
    if env and env.value == REDACTED:
        out.append(Finding('GWA-02', 'high', dep.id,
                           f'LITELLM_MASTER_KEY is written in plain text in `{env.source}`.',
                           'Inject it at runtime from a secret manager, keep it out of version control, '
                           'and rotate it.', setting='LITELLM_MASTER_KEY'))
    if not configured and not env:
        if dep.deployment_found:
            out.append(Finding('GWA-02', 'high', dep.id,
                               'No master key is set, so the proxy serves requests without authentication.',
                               'Set master_key: os.environ/LITELLM_MASTER_KEY and issue virtual keys to callers.',
                               setting='general_settings.master_key'))
        else:
            out.append(Finding('GWA-02', 'medium', dep.id,
                               'The config sets no master key, and no Compose or .env file was found to show '
                               'LITELLM_MASTER_KEY being provided. Without one, the proxy is unauthenticated.',
                               'Set master_key: os.environ/LITELLM_MASTER_KEY, or scan the deployment files too.',
                               setting='general_settings.master_key'))
    return out


@check('GWA-03')
def prompts_in_logs(dep: Deployment) -> list[Finding]:
    out = []
    if truthy(dep.general().get('store_prompts_in_spend_logs', False)):
        out.append(Finding('GWA-03', 'high', dep.id,
                           'store_prompts_in_spend_logs is on: every prompt and response is written to the '
                           'gateway database, next to the spend records.',
                           'Turn it off. If you need content for debugging, log a sample, redact it, and set '
                           'a retention limit.', setting='general_settings.store_prompts_in_spend_logs'))
    ls = dep.litellm()
    callbacks = sorted(set(_list(ls.get('success_callback')) + _list(ls.get('callbacks'))
                           + _list(ls.get('failure_callback'))) - METRICS_ONLY_CALLBACKS)
    if callbacks and not truthy(ls.get('turn_off_message_logging', False)):
        out.append(Finding('GWA-03', 'medium', dep.id,
                           f'Prompts and responses are sent to {", ".join(callbacks)} because '
                           'turn_off_message_logging is not set.',
                           'Set litellm_settings.turn_off_message_logging: true so callbacks receive metadata '
                           'only, or document why each destination may hold message content.',
                           setting='litellm_settings.turn_off_message_logging'))
    return out


@check('GWA-04')
def keys_in_database(dep: Deployment) -> list[Finding]:
    in_db = truthy(dep.general().get('store_model_in_db', False)) or truthy(_env(dep, 'STORE_MODEL_IN_DB') or False)
    if not in_db or dep.general().get('key_management_system'):
        return []
    return [Finding('GWA-04', 'medium', dep.id,
                    'store_model_in_db is on and no key management system is configured, so provider keys '
                    'added through the UI or API are stored in the gateway database. One query can read '
                    'them all, which is what the October 2026 LiteLLM payload did.',
                    'Keep provider keys in a secret manager (general_settings.key_management_system) and '
                    'reference them from the config, or restrict and monitor access to the credentials tables.',
                    setting='general_settings.store_model_in_db')]


@check('GWA-05')
def shared_ui_login(dep: Deployment) -> list[Finding]:
    out = []
    if not truthy(dep.general().get('disable_env_credential_login', False)):
        out.append(Finding('GWA-05', 'medium', dep.id,
                           'The admin UI accepts the shared UI_USERNAME / UI_PASSWORD login (or the master key '
                           'when UI_PASSWORD is unset), so admin actions can\'t be tied to a person.',
                           'Create named proxy_admin users or connect SSO, then set '
                           'general_settings.disable_env_credential_login: true.',
                           setting='general_settings.disable_env_credential_login'))
    ui = dep.env.get('UI_PASSWORD')
    if ui and ui.value == REDACTED:
        out.append(Finding('GWA-05', 'high', dep.id,
                           f'UI_PASSWORD is written in plain text in `{ui.source}`.',
                           'Remove it, rotate it, and move admins to named accounts or SSO.',
                           setting='UI_PASSWORD'))
    return out


@check('GWA-06')
def spend_caps(dep: Deployment) -> list[Finding]:
    ls = dep.litellm()
    out = []
    try:
        cap = float(ls.get('max_budget') or 0)
    except (TypeError, ValueError):
        cap = 0
    if cap <= 0:
        out.append(Finding('GWA-06', 'medium', dep.id,
                           'There is no global spend cap. A leaked virtual key or a runaway agent can spend '
                           'without limit, and stolen gateway access is used to run attackers\' workloads.',
                           'Set litellm_settings.max_budget (and budget_duration) to a limit someone has approved.',
                           setting='litellm_settings.max_budget'))
    upper = ls.get('upperbound_key_generate_params')
    if not isinstance(upper, dict) or 'max_budget' not in upper:
        out.append(Finding('GWA-06', 'low', dep.id,
                           'Virtual keys can be created with no budget limit.',
                           'Set litellm_settings.upperbound_key_generate_params.max_budget so no key can '
                           'exceed it.', setting='litellm_settings.upperbound_key_generate_params'))
    return out


def _tag(ref: str) -> str | None:
    if '@sha256:' in ref:
        return None
    last = ref.rsplit('/', 1)[-1]
    return last.split(':', 1)[1] if ':' in last else 'latest'


@check('GWA-07')
def image_digest(dep: Deployment) -> list[Finding]:
    out = []
    for img in dep.images:
        tag = _tag(img.ref)
        if tag is None:
            continue
        if tag in MUTABLE_TAGS:
            out.append(Finding('GWA-07', 'high', dep.id,
                               f'Service `{img.service}` runs `{img.ref}`, a moving tag. Whatever is published '
                               f'under it next runs with every provider key. LiteLLM\'s October 2026 compromise '
                               f'repointed latest, main-latest and main-stable to a malicious image.',
                               'Pin a reviewed release by digest: image: …litellm@sha256:<digest>.',
                               setting=f'services.{img.service}.image'))
        else:
            out.append(Finding('GWA-07', 'medium', dep.id,
                               f'Service `{img.service}` runs `{img.ref}`, pinned by tag but not by digest. '
                               f'Tags can be moved to different content.',
                               'Add the digest of the reviewed image: image: …litellm:<tag>@sha256:<digest>.',
                               setting=f'services.{img.service}.image'))
    return out


@check('GWA-08')
def tls_verification(dep: Deployment) -> list[Finding]:
    out = []
    if falsy(dep.litellm().get('ssl_verify')):
        out.append(Finding('GWA-08', 'high', dep.id,
                           'ssl_verify is off, so provider certificates aren\'t checked and anyone on the network '
                           'path can read prompts and provider keys.',
                           'Remove ssl_verify: false. For a private CA, set ssl_verify to the CA bundle path.',
                           setting='litellm_settings.ssl_verify'))
    if falsy(_env(dep, 'SSL_VERIFY')):
        out.append(Finding('GWA-08', 'high', dep.id,
                           f'SSL_VERIFY is set to false in `{dep.env["SSL_VERIFY"].source}`.',
                           'Remove it, or point it at a CA bundle instead of disabling verification.',
                           setting='SSL_VERIFY'))
    return out


@check('GWA-09')
def api_docs(dep: Deployment) -> list[Finding]:
    missing = [n for n in ('NO_DOCS', 'NO_REDOC', 'NO_OPENAPI') if not truthy(_env(dep, n) or False)]
    if not missing:
        return []
    return [Finding('GWA-09', 'low', dep.id,
                    f'{", ".join(missing)} {"is" if len(missing) == 1 else "are"} not set to True, so the proxy '
                    'publishes interactive API documentation describing every admin route.',
                    'Set NO_DOCS, NO_REDOC and NO_OPENAPI to "True" in production. Each controls a separate page.',
                    setting=', '.join(missing))]


@check('GWA-10')
def size_limits(dep: Deployment) -> list[Finding]:
    g = dep.general()
    missing = [k for k in ('max_request_size_mb', 'allowed_file_extensions') if k not in g]
    if not missing:
        return []
    return [Finding('GWA-10', 'low', dep.id,
                    f'{" and ".join(missing)} {"is" if len(missing) == 1 else "are"} not set, so request bodies '
                    'and file uploads are not limited.',
                    'Set general_settings.max_request_size_mb and an allowed_file_extensions allowlist '
                    '([] rejects all uploads).', setting=', '.join(f'general_settings.{k}' for k in missing))]


# shortcut: versions come only from the image tag (v1.95.0, main-v1.95.0-stable, 1.95.0@sha256:…);
# a gateway installed with pip, or pinned by digest alone, is NOT ASSESSED rather than guessed.
_VERSION = re.compile(r'(?<![\d.])v?(\d+)\.(\d+)\.(\d+)(rc|dev)?')


def litellm_version(ref: str) -> tuple[int, int, int, int] | None:
    """(major, minor, patch, 1) for a release, (…, 0) for a pre-release, which sorts before it."""
    last = ref.split('@', 1)[0].rsplit('/', 1)[-1]
    if ':' not in last or 'litellm' not in last.split(':', 1)[0]:
        return None
    m = _VERSION.search(last.split(':', 1)[1])
    return (int(m[1]), int(m[2]), int(m[3]), 0 if m[4] else 1) if m else None


def _parse(v: str) -> tuple[int, int, int, int]:
    a, b, c = (int(x) for x in v.split('.'))
    return a, b, c, 1


def _affected(version, spec: str) -> bool:
    for clause in spec.split(','):
        op, v = clause.split()
        bound = _parse(v)
        ok = {'<': version < bound, '<=': version <= bound, '>=': version >= bound, '>': version > bound}[op]
        if not ok:
            return False
    return True


def _fixed_in(spec: str) -> str | None:
    upper = [c.split()[1] for c in spec.split(',') if c.split()[0] == '<']
    return upper[0] if upper else None


def _first_clean(version) -> str | None:
    """The lowest fixed release above `version` that no listed advisory affects. A fix for one
    advisory can still be inside another's range, so each candidate is checked against all."""
    candidates = sorted({f for a in ADVISORIES['advisories'] for s in a['ranges'] if (f := _fixed_in(s))}, key=_parse)
    for c in candidates:
        if _parse(c) > version and not any(_affected(_parse(c), s) for a in ADVISORIES['advisories'] for s in a['ranges']):
            return c
    return None


@check('GWA-11')
def known_advisories(dep: Deployment) -> list[Finding]:
    out = []
    for img in dep.images:
        version = litellm_version(img.ref)
        if not version:
            continue
        hits, malware = [], False
        for adv in ADVISORIES['advisories']:
            spec = next((s for s in adv['ranges'] if _affected(version, s)), None)
            if spec:
                hits.append(adv)
                malware |= bool(adv.get('no_fix'))
        if not hits:
            continue
        shown = '.'.join(map(str, version[:3])) + ('' if version[3] else ' (pre-release)')
        names = ', '.join(a.get('cve') or a['id'] for a in hits[:3]) + (f' and {len(hits) - 3} more' if len(hits) > 3 else '')
        critical = sum(a['severity'] == 'critical' for a in hits)
        msg = (f'Service `{img.service}` runs LiteLLM {shown}, affected by {len(hits)} high or critical '
               f'advisor{"y" if len(hits) == 1 else "ies"} ({critical} critical) known as of '
               f'{ADVISORIES["as_of"]}: {names}. First: {hits[0]["summary"]}.')
        target = _first_clean(version)
        upgrade = (f'Upgrade to {target} or later' if target else
                   'Upgrade to the latest release (no release in the bundled list fixes every advisory)')
        if malware:
            rec = ('Stop this container now: this release was published with credential-harvesting malware. '
                   f'{upgrade}, and rotate the master key and every provider key.')
        else:
            rec = (f'{upgrade} and pin it by digest. If anyone other than admins could sign in while this '
                   'version ran, rotate the master key and provider keys after upgrading.')
        out.append(Finding('GWA-11', 'high', dep.id, msg, rec, setting=f'services.{img.service}.image'))
    return out
