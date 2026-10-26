from __future__ import annotations

from pathlib import Path

import pytest
import yaml


@pytest.fixture
def gateway(tmp_path: Path):
    """Write a LiteLLM config (and optionally a Compose file and .env) into a folder and return it."""
    def make(config: dict | None = None, compose_env: dict | list | None = None, image: str | None = None,
             dotenv: str | None = None, folder: str = 'gw') -> Path:
        d = tmp_path / folder
        d.mkdir(parents=True, exist_ok=True)
        if config is not None:
            (d / 'config.yaml').write_text(yaml.safe_dump(config), encoding='utf-8')
        if image is not None or compose_env is not None:
            svc = {'image': image or 'ghcr.io/berriai/litellm:main-latest'}
            if compose_env is not None:
                svc['environment'] = compose_env
            (d / 'docker-compose.yml').write_text(yaml.safe_dump({'services': {'litellm': svc}}), encoding='utf-8')
        if dotenv is not None:
            (d / '.env').write_text(dotenv, encoding='utf-8')
        return d
    return make


HARDENED = {
    'model_list': [{'model_name': 'm', 'litellm_params': {'model': 'openai/gpt-4o', 'api_key': 'os.environ/OPENAI_API_KEY'}}],
    'general_settings': {'master_key': 'os.environ/LITELLM_MASTER_KEY', 'disable_env_credential_login': True,
                         'max_request_size_mb': 25, 'allowed_file_extensions': ['.txt']},
    'litellm_settings': {'max_budget': 100, 'upperbound_key_generate_params': {'max_budget': 10}},
}
PINNED = 'ghcr.io/berriai/litellm:v1.106.2@sha256:' + '0' * 64
DOCS_OFF = {'NO_DOCS': 'True', 'NO_REDOC': 'True', 'NO_OPENAPI': 'True', 'LITELLM_MASTER_KEY': '${LITELLM_MASTER_KEY}'}
