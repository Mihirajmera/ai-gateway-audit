"""Discovery and parsing. Files are only read, never executed; YAML is loaded with safe_load.
Plain-text secrets are redacted here, before anything is checked, written or hashed into a
report, so no output can contain them."""
from __future__ import annotations

import hashlib
import re
import sys
from pathlib import Path

import yaml

from .model import REDACTED, Deployment, EnvVar, Image, Source

SKIP_DIRS = {'.git', 'node_modules', '.venv', 'venv', '__pycache__', 'dist', 'build', '.tox'}
MAX_BYTES = 5 * 1024 * 1024
LITELLM_SECTIONS = {'model_list', 'general_settings', 'litellm_settings', 'router_settings', 'credential_list'}

# Setting names that hold a credential, matched on the end of YAML keys and environment variable
# names: api_key, OPENAI_API_KEY, UI_PASSWORD, HF_TOKEN. Not max_tokens or key_management_system.
SECRET_NAME = re.compile(r'(^|_)(api_?key|key|secret|token|password|passwd|credentials?|private_key|auth_key|'
                         r'access_key|secret_access_key|session_token|webhook_secret)$', re.I)
# Connection strings with a password in them: postgresql://user:password@host/db
URL_WITH_PASSWORD = re.compile(r'^[a-z][a-z0-9+.-]*://[^/\s:@]+:[^@\s]+@', re.I)
URL_NAME = re.compile(r'(database_url|redis_url|_url$|_dsn$)', re.I)
SUBSTITUTION = re.compile(r'^\$\{?[A-Za-z_][A-Za-z0-9_]*')


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_literal(value) -> bool:
    """A value written into the file itself, rather than a reference to somewhere else."""
    if not isinstance(value, str):
        return value is not None and not isinstance(value, (bool, dict, list))
    v = value.strip()
    return bool(v) and not v.startswith('os.environ/') and not SUBSTITUTION.match(v)


def is_secret(name: str, value) -> bool:
    if not isinstance(value, str) or not is_literal(value):
        return False
    if URL_NAME.search(name):
        return bool(URL_WITH_PASSWORD.match(str(value)))
    return bool(SECRET_NAME.search(name))


def redact(obj, path: str, found: list[str]):
    """Copy of a parsed config with plain-text secrets replaced, recording where each was."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            p = f'{path}.{k}' if path else str(k)
            if isinstance(v, (dict, list)):
                out[k] = redact(v, p, found)
            elif is_secret(str(k), v):
                found.append(p)
                out[k] = REDACTED
            else:
                out[k] = v
        return out
    if isinstance(obj, list):
        return [redact(v, f'{path}[{i}]', found) for i, v in enumerate(obj)]
    return obj


def parse_env_file(text: str) -> dict[str, str | None]:
    env = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        if line.startswith('export '):
            line = line[7:].lstrip()
        if '=' not in line:
            env[line] = None
            continue
        k, v = line.split('=', 1)
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in '"\'':
            v = v[1:-1]
        else:
            v = v.split(' #', 1)[0].strip()
        env[k.strip()] = v
    return env


def compose_environment(env) -> dict[str, str | None]:
    if isinstance(env, dict):
        return {str(k): (None if v is None else str(v)) for k, v in env.items()}
    if isinstance(env, list):
        out = {}
        for item in env:
            if isinstance(item, str):
                k, _, v = item.partition('=')
                out[k.strip()] = v if _ else None
        return out
    return {}


def _env_files(spec) -> list[str]:
    items = spec if isinstance(spec, list) else [spec]
    out = []
    for item in items:
        if isinstance(item, str):
            out.append(item)
        elif isinstance(item, dict) and isinstance(item.get('path'), str):
            out.append(item['path'])
    return out


def _load_yaml(path: Path):
    try:
        if path.stat().st_size > MAX_BYTES:
            return None
        return yaml.safe_load(path.read_text(encoding='utf-8', errors='replace'))
    except (yaml.YAMLError, OSError, ValueError, RecursionError) as exc:
        print(f'skipped {path}: {type(exc).__name__}', file=sys.stderr)
        return None


def _walk(root: Path):
    if root.is_file():
        yield root
        return
    for p in sorted(root.rglob('*')):
        if p.is_file() and not any(part in SKIP_DIRS for part in p.relative_to(root).parts[:-1]):
            yield p


def _display(path: Path, root: Path) -> str:
    try:
        rel = path.resolve().relative_to(root.resolve() if root.is_dir() else root.resolve().parent)
        return rel.as_posix()
    except ValueError:
        return path.as_posix()


class _Builder:
    def __init__(self):
        self.by_folder: dict[Path, Deployment] = {}
        self.seen: set[Path] = set()

    def get(self, folder: Path, root: Path) -> Deployment:
        key = folder.resolve()
        if key not in self.by_folder:
            base = root if root.is_dir() else root.parent
            try:
                rel = key.relative_to(base.resolve()).as_posix()
            except ValueError:
                rel = folder.as_posix()
            name = base.resolve().name if rel in ('', '.') else rel
            self.by_folder[key] = Deployment(id=re.sub(r'[^A-Za-z0-9_.-]+', '-', name).strip('-') or 'gateway',
                                             folder=rel or '.')
        return self.by_folder[key]

    def add_source(self, dep: Deployment, path: Path, root: Path, kind: str) -> str | None:
        key = path.resolve()
        if key in self.seen:
            return None
        self.seen.add(key)
        shown = _display(path, root)
        dep.sources.append(Source(shown, kind, file_sha256(path)))
        return shown

    def add_env(self, dep: Deployment, env: dict[str, str | None], source: str):
        dep.deployment_found = True
        for name, value in env.items():
            literal = is_literal(value)
            secret = is_secret(name, value)
            if secret:
                dep.secrets.append((name, source))
            dep.env[name] = EnvVar(name, literal, REDACTED if secret else value, source)


def discover(paths: list[Path]) -> list[Deployment]:
    b = _Builder()
    pending_env: list[tuple[Path, Path]] = []
    for root in paths:
        for path in _walk(root):
            name = path.name.lower()
            if name == '.env' or name.endswith('.env'):
                pending_env.append((path, root))
                continue
            if path.suffix.lower() not in ('.yaml', '.yml'):
                continue
            data = _load_yaml(path)
            if not isinstance(data, dict):
                continue
            if LITELLM_SECTIONS & set(map(str, data)):
                _add_config(b, path, root, data)
            elif isinstance(data.get('services'), dict):
                _add_compose(b, path, root, data)

    for path, root in pending_env:                       # .env files join a deployment in their folder
        dep = b.by_folder.get(path.parent.resolve())
        if dep is not None:
            _add_env_file(b, dep, path, root)
    return [d for d in b.by_folder.values() if d.config_found or d.images]


def _add_config(b: _Builder, path: Path, root: Path, data: dict):
    dep = b.get(path.parent, root)
    shown = b.add_source(dep, path, root, 'litellm-config')
    if shown is None:
        return
    found: list[str] = []
    clean = redact(data, '', found)
    dep.secrets += [(p, shown) for p in found]
    for section, value in clean.items():                 # several configs in one folder are merged
        current = dep.config.get(section)
        if isinstance(current, dict) and isinstance(value, dict):
            current.update(value)
        elif isinstance(current, list) and isinstance(value, list):
            current.extend(value)
        else:
            dep.config[section] = value
    dep.config_found = True


def _add_compose(b: _Builder, path: Path, root: Path, data: dict):
    services = {n: s for n, s in data['services'].items()
                if isinstance(s, dict) and 'litellm' in str(s.get('image', '')).lower()}
    if not services:
        return
    dep = b.get(path.parent, root)
    shown = b.add_source(dep, path, root, 'compose')
    if shown is None:
        return
    dep.deployment_found = True
    for name, svc in services.items():
        dep.images.append(Image(str(svc['image']), str(name), shown))
        b.add_env(dep, compose_environment(svc.get('environment')), shown)
        for ref in _env_files(svc.get('env_file', [])):
            env_path = (path.parent / ref)
            if env_path.is_file():
                _add_env_file(b, dep, env_path, root)


def _add_env_file(b: _Builder, dep: Deployment, path: Path, root: Path):
    shown = b.add_source(dep, path, root, 'env')
    if shown is None:
        return
    try:
        text = path.read_text(encoding='utf-8', errors='replace')
    except OSError:
        return
    b.add_env(dep, parse_env_file(text), shown)
