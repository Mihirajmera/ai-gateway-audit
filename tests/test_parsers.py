from __future__ import annotations

import copy

from ai_gateway_audit.model import REDACTED
from ai_gateway_audit.parsers import discover, is_secret, parse_env_file
from conftest import HARDENED


def test_secret_names_match_credentials_not_counts():
    assert is_secret('api_key', 'abc123')
    assert is_secret('OPENAI_API_KEY', 'abc123')
    assert is_secret('UI_PASSWORD', 'hunter2')
    assert is_secret('LITELLM_SALT_KEY', 'salt')
    assert not is_secret('max_tokens', '4096')
    assert not is_secret('key_management_system', 'aws_kms')
    assert not is_secret('max_tokens', 4096)


def test_references_are_not_secrets():
    assert not is_secret('api_key', 'os.environ/OPENAI_API_KEY')
    assert not is_secret('OPENAI_API_KEY', '${OPENAI_API_KEY}')
    assert not is_secret('OPENAI_API_KEY', '$OPENAI_API_KEY')
    assert not is_secret('OPENAI_API_KEY', '')


def test_connection_strings_are_secret_only_with_a_password():
    assert is_secret('DATABASE_URL', 'postgresql://user:pw@db:5432/litellm')
    assert not is_secret('DATABASE_URL', 'postgresql://db:5432/litellm')
    assert not is_secret('database_url', 'os.environ/DATABASE_URL')


def test_config_secrets_are_redacted_and_located(gateway):
    cfg = copy.deepcopy(HARDENED)
    cfg['model_list'][0]['litellm_params']['api_key'] = 'plain-text-key'
    cfg['router_settings'] = {'redis_password': 'redis-pw'}
    [dep] = discover([gateway(cfg)])
    assert dep.config['model_list'][0]['litellm_params']['api_key'] == REDACTED
    assert dep.config['router_settings']['redis_password'] == REDACTED
    assert {s for s, _ in dep.secrets} == {'model_list[0].litellm_params.api_key', 'router_settings.redis_password'}


def test_compose_and_env_files_join_the_config_in_the_same_folder(gateway):
    d = gateway(HARDENED, compose_env=['NO_DOCS=True', 'LITELLM_MASTER_KEY'], image='ghcr.io/berriai/litellm:main-stable',
                dotenv='export UI_PASSWORD="hunter2"  # comment\nNO_REDOC=True\n')
    [dep] = discover([d])
    assert {s.type for s in dep.sources} == {'litellm-config', 'compose', 'env'}
    assert dep.images[0].ref == 'ghcr.io/berriai/litellm:main-stable'
    assert dep.env['NO_DOCS'].value == 'True' and dep.env['NO_REDOC'].value == 'True'
    assert dep.env['LITELLM_MASTER_KEY'].literal is False
    assert dep.env['UI_PASSWORD'].value == REDACTED
    assert dep.deployment_found


def test_compose_env_file_reference_is_read(gateway, tmp_path):
    d = gateway(HARDENED)
    (d / 'secrets.list').write_text('OPENAI_API_KEY=abc\n', encoding='utf-8')
    (d / 'docker-compose.yml').write_text(
        'services:\n  proxy:\n    image: ghcr.io/berriai/litellm:v1\n    env_file: [secrets.list]\n', encoding='utf-8')
    [dep] = discover([d])
    assert ('OPENAI_API_KEY', 'secrets.list') in dep.secrets          # paths are relative to the scanned folder


def test_folders_without_litellm_are_ignored(gateway, tmp_path):
    other = tmp_path / 'web'
    other.mkdir()
    (other / 'docker-compose.yml').write_text('services:\n  web:\n    image: nginx:1\n', encoding='utf-8')
    (other / '.env').write_text('API_KEY=x\n', encoding='utf-8')
    (other / 'values.yaml').write_text('replicas: 2\n', encoding='utf-8')
    gateway(HARDENED)
    assert [d.id for d in discover([tmp_path])] == ['gw']


def test_malformed_yaml_does_not_abort_the_scan(gateway, tmp_path):
    d = gateway(HARDENED)
    (d / 'broken.yaml').write_text('model_list: [unclosed\n', encoding='utf-8')
    assert len(discover([tmp_path])) == 1


def test_env_file_parsing():
    env = parse_env_file('# c\nA=1\nexport B="two words"\nC=\'x\'\nD=3 # trailing\nE\n')
    assert env == {'A': '1', 'B': 'two words', 'C': 'x', 'D': '3', 'E': None}
