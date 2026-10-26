"""Normalized deployment model. LiteLLM configs, Docker Compose files and .env files found
in the same folder are merged into one Deployment, so the checks never care which file a
setting came from."""
from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_ORDER = {'high': 3, 'medium': 2, 'low': 1}
REDACTED = '[REDACTED]'


@dataclass
class Source:
    path: str                                # as given, or relative to the scanned folder
    type: str                                # litellm-config | compose | env
    sha256: str                              # of the file's bytes, so the evidence pins exactly what was read


@dataclass
class EnvVar:
    name: str
    literal: bool                            # a value is written in the file (not ${VAR} or empty)
    value: str | None                        # kept only for non-secret settings; secrets become REDACTED
    source: str


@dataclass
class Image:
    ref: str                                 # e.g. ghcr.io/berriai/litellm:main-stable
    service: str
    source: str


@dataclass
class Deployment:
    id: str
    folder: str
    sources: list[Source] = field(default_factory=list)
    config: dict = field(default_factory=dict)            # merged LiteLLM config.yaml
    config_found: bool = False
    env: dict[str, EnvVar] = field(default_factory=dict)  # from compose environment and .env files
    images: list[Image] = field(default_factory=list)
    secrets: list[tuple[str, str]] = field(default_factory=list)  # (setting path, source) with a plain-text secret
    deployment_found: bool = False                        # a compose file or .env describes how it runs

    def general(self) -> dict:
        g = self.config.get('general_settings')
        return g if isinstance(g, dict) else {}

    def litellm(self) -> dict:
        s = self.config.get('litellm_settings')
        return s if isinstance(s, dict) else {}


@dataclass
class Finding:
    check_id: str
    severity: str                            # high | medium | low
    deployment_id: str
    message: str
    recommendation: str
    setting: str | None = None               # the config path or variable the finding is about
    exception: dict | None = None            # a valid, unexpired exception that covers this finding
