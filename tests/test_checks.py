from __future__ import annotations

import copy

import pytest

from ai_gateway_audit.checks import CONTROLS, REGISTRY, run_all
from ai_gateway_audit.parsers import discover
from conftest import DOCS_OFF, HARDENED, PINNED


def results(gateway, config=HARDENED, **kw):
    [dep] = discover([gateway(config, **kw)])
    return run_all(dep)


def ids(res, check_id):
    return [(f.severity, f.setting) for f in res[check_id] or []]


def with_settings(**sections):
    cfg = copy.deepcopy(HARDENED)
    for section, values in sections.items():
        cfg.setdefault(section, {}).update(values)
    return cfg


def test_every_registered_check_is_in_the_catalog():
    assert set(REGISTRY) == set(CONTROLS)


def test_hardened_gateway_passes_everything(gateway):
    res = results(gateway, compose_env=DOCS_OFF, image=PINNED)
    assert {cid: fs for cid, fs in res.items() if fs} == {}
    assert all(fs is not None for fs in res.values())


def test_deployment_checks_are_not_assessed_without_deployment_files(gateway):
    res = results(gateway)
    assert res['GWA-07'] is None and res['GWA-09'] is None
    assert res['GWA-01'] == []


def test_plaintext_provider_key(gateway):
    cfg = copy.deepcopy(HARDENED)
    cfg['model_list'][0]['litellm_params']['api_key'] = 'plain'
    assert ids(results(gateway, cfg), 'GWA-01') == [('high', 'model_list[0].litellm_params.api_key')]


@pytest.mark.parametrize('config_key,env,expected', [
    ('sk-1234', None, [('high', 'general_settings.master_key')]),
    ('os.environ/LITELLM_MASTER_KEY', {'LITELLM_MASTER_KEY': 'literal-key'}, [('high', 'LITELLM_MASTER_KEY')]),
    (None, {'NO_DOCS': 'True'}, [('high', 'general_settings.master_key')]),     # deployment known, no key
    (None, None, [('medium', 'general_settings.master_key')]),                  # can't tell
])
def test_master_key(gateway, config_key, env, expected):
    cfg = copy.deepcopy(HARDENED)
    if config_key:
        cfg['general_settings']['master_key'] = config_key
    else:
        del cfg['general_settings']['master_key']
    res = results(gateway, cfg, compose_env=env) if env else results(gateway, cfg)
    assert ids(res, 'GWA-02') == expected
    assert ids(res, 'GWA-01') == []                     # reported by GWA-02, not twice


def test_master_key_from_environment_reference_passes(gateway):
    cfg = copy.deepcopy(HARDENED)
    del cfg['general_settings']['master_key']
    assert ids(results(gateway, cfg, compose_env={'LITELLM_MASTER_KEY': '${KEY}'}), 'GWA-02') == []


def test_prompts_in_spend_logs_and_callbacks(gateway):
    res = results(gateway, with_settings(general_settings={'store_prompts_in_spend_logs': True},
                                         litellm_settings={'success_callback': ['langfuse', 'prometheus']}))
    assert ids(res, 'GWA-03') == [('high', 'general_settings.store_prompts_in_spend_logs'),
                                  ('medium', 'litellm_settings.turn_off_message_logging')]


def test_metrics_only_callbacks_and_message_logging_off_pass(gateway):
    assert ids(results(gateway, with_settings(litellm_settings={'callbacks': 'prometheus'})), 'GWA-03') == []
    assert ids(results(gateway, with_settings(litellm_settings={'callbacks': ['s3'],
                                                                'turn_off_message_logging': True})), 'GWA-03') == []


def test_keys_in_database(gateway):
    assert ids(results(gateway, with_settings(general_settings={'store_model_in_db': True})), 'GWA-04') == \
        [('medium', 'general_settings.store_model_in_db')]
    assert ids(results(gateway, HARDENED, compose_env={'STORE_MODEL_IN_DB': 'True'}), 'GWA-04') != []
    assert ids(results(gateway, with_settings(general_settings={'store_model_in_db': True,
                                                                'key_management_system': 'aws_kms'})), 'GWA-04') == []


def test_shared_ui_login(gateway):
    cfg = with_settings(general_settings={'disable_env_credential_login': False})
    assert ids(results(gateway, cfg, compose_env={'UI_PASSWORD': 'pw'}), 'GWA-05') == \
        [('medium', 'general_settings.disable_env_credential_login'), ('high', 'UI_PASSWORD')]


def test_spend_caps(gateway):
    cfg = copy.deepcopy(HARDENED)
    cfg['litellm_settings'] = {'max_budget': 0}
    assert [s for s, _ in ids(results(gateway, cfg), 'GWA-06')] == ['medium', 'low']


@pytest.mark.parametrize('image,expected', [
    ('ghcr.io/berriai/litellm:main-stable', 'high'),
    ('ghcr.io/berriai/litellm', 'high'),                       # no tag means latest
    ('localhost:5000/litellm:v1.106.2', 'medium'),             # registry port is not a tag
    (PINNED, None),
])
def test_image_pinning(gateway, image, expected):
    found = ids(results(gateway, compose_env=DOCS_OFF, image=image), 'GWA-07')
    assert [s for s, _ in found] == ([expected] if expected else [])


def test_tls_verification(gateway):
    assert ids(results(gateway, with_settings(litellm_settings={'ssl_verify': False})), 'GWA-08') == \
        [('high', 'litellm_settings.ssl_verify')]
    assert ids(results(gateway, with_settings(litellm_settings={'ssl_verify': '/etc/ssl/ca.pem'})), 'GWA-08') == []
    assert ids(results(gateway, compose_env={'SSL_VERIFY': 'False'}), 'GWA-08') == [('high', 'SSL_VERIFY')]


def test_api_docs(gateway):
    found = ids(results(gateway, compose_env={'NO_DOCS': 'True'}, image=PINNED), 'GWA-09')
    assert found == [('low', 'NO_REDOC, NO_OPENAPI')]


def test_size_limits(gateway):
    cfg = copy.deepcopy(HARDENED)
    del cfg['general_settings']['allowed_file_extensions']
    assert ids(results(gateway, cfg), 'GWA-10') == [('low', 'general_settings.allowed_file_extensions')]
