"""Credential compatibility tests; never access the real OS keychain."""
import sys
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi import HTTPException

from services.shared.secrets import Secrets, SecretLoadError
from services.brain_service.routes.health import readiness_check


@pytest.fixture(autouse=True)
def credentials(monkeypatch):
    import os
    for name in list(os.environ):
        if name.startswith('CORELINE_') or name in (
            'ANTHROPIC_API_KEY', 'CLAUDE_API_KEY', 'SLACK_BOT_TOKEN',
            'JIRA_WEBHOOK_SECRET', 'JIRA_API_TOKEN', 'JIRA_EMAIL',
        ):
            monkeypatch.delenv(name)
    entries = {}
    monkeypatch.setitem(sys.modules, 'keyring', SimpleNamespace(
        get_password=lambda service, key: entries.get((service, key))))
    return entries


@pytest.mark.parametrize('name,getter', [
    ('SLACK_BOT_TOKEN', 'get_slack_bot_token'),
    ('JIRA_WEBHOOK_SECRET', 'get_jira_webhook_secret'),
    ('ANTHROPIC_API_KEY', 'get_claude_api_key'),
    ('JIRA_API_TOKEN', 'get_jira_api_token'),
    ('JIRA_EMAIL', 'get_jira_email'),
])
def test_precedence_and_legacy_fallback(monkeypatch, credentials, name, getter):
    resolve = getattr(Secrets(), getter)
    credentials['Coreline', name.lower()] = 'keychain'
    credentials['secops-secure-enclave', 'CORELINE_' + name] = 'old-keychain'
    monkeypatch.setenv(name, 'legacy-env')
    monkeypatch.setenv('CORELINE_' + name, 'preferred-env')
    assert resolve() == 'preferred-env'
    monkeypatch.setenv('CORELINE_' + name, '')
    assert resolve() == 'legacy-env'
    monkeypatch.delenv(name)
    assert resolve() == 'keychain'
    del credentials['Coreline', name.lower()]
    assert resolve() == 'old-keychain'
    del credentials['secops-secure-enclave', 'CORELINE_' + name]
    credentials['secops-secure-enclave', name] = 'old-unprefixed-keychain'
    assert resolve() == 'old-unprefixed-keychain'


def test_legacy_claude_aliases(monkeypatch, credentials):
    secrets = Secrets()
    credentials['Coreline', 'claude_api_key'] = 'old-keychain'
    assert secrets.get_claude_api_key() == 'old-keychain'
    monkeypatch.setenv('CLAUDE_API_KEY', 'old-env')
    assert secrets.get_claude_api_key() == 'old-env'
    monkeypatch.setenv('ANTHROPIC_API_KEY', 'anthropic')
    assert secrets.get_claude_api_key() == 'anthropic'
    monkeypatch.setenv('CORELINE_CLAUDE_API_KEY', 'prefixed')
    assert secrets.get_claude_api_key() == 'prefixed'
    monkeypatch.setenv('CORELINE_ANTHROPIC_API_KEY', 'canonical')
    assert secrets.get_claude_api_key() == 'canonical'
    assert secrets.get('CLAUDE_API_KEY') == 'canonical'


def test_missing_or_unavailable_keychain(monkeypatch):
    def unavailable(*args):
        raise RuntimeError('keychain locked')
    monkeypatch.setitem(sys.modules, 'keyring', SimpleNamespace(get_password=unavailable))
    assert Secrets(fail_fast=False).get_slack_bot_token() is None
    assert Secrets().get('SLACK_BOT_TOKEN', required=False) is None
    with pytest.raises(SecretLoadError, match='CORELINE_SLACK_BOT_TOKEN'):
        Secrets().get_slack_bot_token()
    monkeypatch.setitem(sys.modules, 'keyring', None)
    assert Secrets(fail_fast=False).get_slack_bot_token() is None




def test_brain_provider_uses_shared_legacy_keychain(credentials, monkeypatch):
    from services.brain_service import _lib_shim
    from unittest.mock import Mock
    credentials['Coreline', 'claude_api_key'] = 'legacy-provider-key'
    client = Mock()
    monkeypatch.setitem(sys.modules, 'anthropic', SimpleNamespace(Anthropic=client))
    provider = _lib_shim.default_pir_provider('test-model')
    assert isinstance(provider, _lib_shim.ClaudePIRProvider)
    client.assert_called_once_with(api_key='legacy-provider-key')
    credentials.clear()
    assert isinstance(_lib_shim.default_pir_provider('test-model'), _lib_shim.FakePIRProvider)


@pytest.mark.parametrize('name', ['SLACK_BOT_TOKEN', 'JIRA_WEBHOOK_SECRET', 'ANTHROPIC_API_KEY', 'JIRA_API_TOKEN', 'JIRA_EMAIL'])
@pytest.mark.parametrize('modern,legacy,keychain,winner', [
    ('modern', None, None, 'modern'), (None, 'legacy', None, 'legacy'),
    (None, None, 'keychain', 'keychain'), ('modern', 'legacy', None, 'modern'),
    ('modern', None, 'keychain', 'modern'), (None, 'legacy', 'keychain', 'legacy'),
    ('modern', 'legacy', 'keychain', 'modern'), (None, None, None, None),
    ('', '', 'keychain', 'keychain'), (' \t', 'legacy', 'keychain', 'legacy'),
])
def test_full_precedence_matrix(monkeypatch, credentials, name, modern, legacy, keychain, winner):
    if modern is not None:
        monkeypatch.setenv('CORELINE_' + name, modern)
    if legacy is not None:
        monkeypatch.setenv(name, legacy)
    credentials['Coreline', name.lower()] = keychain
    assert Secrets(fail_fast=False).get(name) == winner


@pytest.mark.parametrize('bad', [b'not-text', {'secret': 'not-text'}, 42, True, '', ' \t'])
def test_malformed_keychain_is_not_a_credential(credentials, bad):
    credentials['Coreline', 'slack_bot_token'] = bad
    assert Secrets(fail_fast=False).get_slack_bot_token() is None
    with pytest.raises(SecretLoadError):
        Secrets().get_slack_bot_token()


@pytest.fixture
def brain_runtime(monkeypatch, tmp_path):
    from contextlib import asynccontextmanager
    from fastapi import FastAPI
    from services.brain_service import main
    from services.brain_service.config import Settings
    from unittest.mock import Mock
    config = Settings(_env_file=None, pir_output_dir=tmp_path / 'drafts')
    monkeypatch.setattr(main, 'get_settings', lambda: config)
    client = AsyncMock()
    monkeypatch.setattr(main.redis, 'from_url', lambda *a, **kw: client)
    subscriber = SimpleNamespace(start=AsyncMock(), stop=Mock())
    monkeypatch.setattr(main, 'PIRSubscriber', lambda **kw: subscriber)
    sdk = Mock()
    monkeypatch.setitem(sys.modules, 'anthropic', SimpleNamespace(Anthropic=sdk))

    @asynccontextmanager
    async def running():
        app = FastAPI()
        async with main.lifespan(app):
            yield SimpleNamespace(app=app)
    return SimpleNamespace(running=running, redis=client, sdk=sdk, config=config)


def _brain_credentials(monkeypatch, entries, source):
    for name in ('ANTHROPIC_API_KEY', 'SLACK_BOT_TOKEN', 'JIRA_API_TOKEN', 'JIRA_EMAIL'):
        if source in ('Coreline', 'secops-secure-enclave'):
            key = name.lower() if source == 'Coreline' else 'CORELINE_' + name
            entries[source, key] = 'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91'
        else:
            monkeypatch.setenv(('CORELINE_' if source == 'modern' else '') + name,
                               'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91')


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['modern', 'legacy', 'Coreline', 'secops-secure-enclave'])
async def test_actual_brain_startup_and_readiness(monkeypatch, credentials, brain_runtime, source, capsys):
    _brain_credentials(monkeypatch, credentials, source)
    async with brain_runtime.running() as request:
        result = await readiness_check(request)
        assert result['checks'] == {'redis': True, 'credentials': True, 'provider': True}
        assert request.app.state.pir_orchestrator.pir_provider._client is brain_runtime.sdk.return_value
        # The active provider retains its initialized configuration if sources rotate.
        credentials.clear()
        monkeypatch.delenv('CORELINE_ANTHROPIC_API_KEY', raising=False)
        monkeypatch.delenv('ANTHROPIC_API_KEY', raising=False)
        assert (await readiness_check(request))['status'] == 'ready'
    assert 'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91' not in capsys.readouterr().out


@pytest.mark.asyncio
@pytest.mark.parametrize('failure', ['missing', 'empty', 'whitespace', 'sdk', 'constructor', 'redis'])
async def test_brain_startup_failures_are_safe(monkeypatch, credentials, brain_runtime, failure, capsys, tmp_path):
    _brain_credentials(monkeypatch, credentials, 'modern')
    canary = 'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91'
    if failure == 'missing':
        monkeypatch.delenv('CORELINE_ANTHROPIC_API_KEY')
    elif failure in ('empty', 'whitespace'):
        monkeypatch.setenv('CORELINE_ANTHROPIC_API_KEY', '' if failure == 'empty' else ' \t')
    elif failure == 'sdk':
        monkeypatch.setitem(sys.modules, 'anthropic', None)
    elif failure == 'constructor':
        brain_runtime.sdk.side_effect = RuntimeError(canary)
    else:
        import redis.exceptions
        brain_runtime.redis.ping.side_effect = redis.exceptions.ConnectionError(canary)
    with pytest.raises(SystemExit) as error:
        async with brain_runtime.running():
            pytest.fail('startup unexpectedly succeeded')
    assert error.value.code == 1
    assert canary not in capsys.readouterr().out
    assert not (tmp_path / 'drafts').exists()


@pytest.mark.asyncio
async def test_readiness_requires_initialized_provider_and_redis(monkeypatch, credentials, brain_runtime, capsys):
    _brain_credentials(monkeypatch, credentials, 'modern')
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=AsyncMock())))
    with pytest.raises(HTTPException) as error:
        await readiness_check(request)
    assert not error.value.detail['checks']['provider']
    async with brain_runtime.running() as request:
        import redis.exceptions
        brain_runtime.redis.ping.side_effect = redis.exceptions.ConnectionError('CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91')
        with pytest.raises(HTTPException) as error:
            await readiness_check(request)
        assert error.value.status_code == 503
        assert error.value.detail['checks'] == {'redis': False, 'credentials': True, 'provider': True}
    assert 'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91' not in capsys.readouterr().out


@pytest.mark.parametrize('service', ['brain_service', 'jira_webhook_listener', 'slack_orchestrator'])
def test_settings_do_not_render_redis_password_or_invalid_input(service, tmp_path):
    from importlib import import_module
    from pydantic import ValidationError
    canary = 'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91'
    settings_type = import_module(f'services.{service}.config').Settings
    config = settings_type(_env_file=None, redis_url=f'redis://user:{canary}@localhost/0')
    assert canary not in repr(config)
    assert canary not in config.model_dump_json()
    assert canary not in repr(config.model_dump())
    env_file = tmp_path / 'invalid.env'
    env_file.write_text(f'CORELINE_SLACK_BOT_TOKEN={canary}\n')
    with pytest.raises(ValidationError) as error:
        settings_type(_env_file=env_file)
    assert canary not in str(error.value)


@pytest.mark.asyncio
@pytest.mark.parametrize('source', ['modern', 'legacy', 'Coreline', 'jira-keychain'])
async def test_jira_real_startup_uses_shared_credentials(monkeypatch, credentials, tmp_path, source, capsys):
    from fastapi import FastAPI
    from services.jira_webhook_listener import main
    from services.jira_webhook_listener.config import Settings
    canary = 'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91'
    if source in ('modern', 'legacy'):
        monkeypatch.setenv(('CORELINE_' if source == 'modern' else '') + 'JIRA_WEBHOOK_SECRET', canary)
    elif source == 'Coreline':
        credentials['Coreline', 'jira_webhook_secret'] = canary
    else:
        credentials['coreline-jira-webhook-listener', 'jira-webhook-secret'] = canary
    config = Settings(_env_file=None, redis_url=f'redis://user:{canary}@localhost/0')
    monkeypatch.setattr(main, 'get_settings', lambda: config)
    monkeypatch.setattr(main.redis, 'from_url', lambda *a, **kw: AsyncMock())
    app = FastAPI()
    async with main.lifespan(app):
        assert app.state.hmac_verifier.secret == canary.encode()
        result = await main.health.readiness_probe(SimpleNamespace(app=app))
        assert result['status'] == 'ready'
    assert canary not in capsys.readouterr().out


@pytest.mark.asyncio
async def test_provider_failure_does_not_write_or_leak(monkeypatch, credentials, tmp_path, capsys):
    from services.brain_service.handlers.pir_orchestrator import PIROrchestrator
    from services.brain_service.models.incident_event import IncidentEvent
    from services.brain_service.routes.pir import generate_pir
    from core.incident.workspace import IncidentWorkspace
    import fakeredis.aioredis
    from unittest.mock import Mock
    canary = 'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91'
    ws = IncidentWorkspace.declare(tmp_path / 'incidents', title='Preserve', severity='SEV2', actor='tester')
    before = {p: p.read_bytes() for p in ws.home.rglob('*') if p.is_file()}
    provider = Mock()
    provider.generate.side_effect = RuntimeError(canary)
    client = fakeredis.aioredis.FakeRedis(decode_responses=True)
    try:
        orchestrator = PIROrchestrator(client, tmp_path / 'drafts', pir_provider=provider)
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pir_orchestrator=orchestrator)))
        event = IncidentEvent(incident_id='INC-42', summary='test', priority='P2', severity='High',
                              detection_time='2026-09-19T00:00:00Z', webhook_event='jira:issue_updated',
                              jira_url='https://example.test/INC-42')
        with pytest.raises(HTTPException) as error:
            await generate_pir(event, request)
        assert error.value.status_code == 503
        assert canary not in str(error.value.detail)
        assert not list((tmp_path / 'drafts').glob('*.md'))
        assert before == {p: p.read_bytes() for p in ws.home.rglob('*') if p.is_file()}
        assert ws.verify()['ok']
        assert canary not in capsys.readouterr().out
    finally:
        await client.aclose()


@pytest.mark.asyncio
@pytest.mark.parametrize('service', ['jira_webhook_listener', 'slack_orchestrator'])
async def test_dependency_readiness_errors_do_not_leak(service, capsys):
    import importlib
    import redis.exceptions
    canary = 'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91'
    health = importlib.import_module(f'services.{service}.routes.health')
    client = AsyncMock()
    client.ping.side_effect = redis.exceptions.ConnectionError(canary)
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=client)))
    if service == 'jira_webhook_listener':
        result = await health.readiness_probe(request)
        assert result.status_code == 503
        assert canary.encode() not in result.body
    else:
        with pytest.raises(HTTPException) as error:
            await health.readiness_check(request)
        assert error.value.status_code == 503
        assert canary not in str(error.value.detail)
    assert canary not in capsys.readouterr().out


def test_jira_packet_does_not_include_url_credentials():
    from services.brain_service._lib_shim import PIRDataAssembler
    canary = 'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91'
    packet = PIRDataAssembler(f'https://user:{canary}@example.test/?token={canary}').assemble('INC-42')
    assert canary not in packet


@pytest.mark.asyncio
@pytest.mark.parametrize('service', ['brain', 'slack'])
@pytest.mark.parametrize('malformed', [True, False])
async def test_subscriber_rejects_bad_payload_without_logging_contents(service, malformed, capsys):
    import json
    from services.brain_service.handlers.pir_subscriber import PIRSubscriber
    from services.slack_orchestrator.handlers.incident_subscriber import IncidentSubscriber
    canary = 'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91'
    if service == 'brain':
        subscriber = PIRSubscriber(redis_client=AsyncMock(), on_pir_callback=AsyncMock())
    else:
        subscriber = IncidentSubscriber(redis_client=AsyncMock(), on_incident_callback=AsyncMock())
    data = canary if malformed else json.dumps({'incident_id': 'INC-42', 'priority': {'secret': canary}})
    await subscriber._handle_message(data)
    assert canary not in capsys.readouterr().out


@pytest.mark.parametrize('model,key', [('', 'key'), (' \t', 'key'), ('model', ''), ('model', ' \t')])
def test_explicit_provider_rejects_blank_configuration(model, key):
    from services.brain_service._lib_shim import ClaudePIRProvider
    with pytest.raises(SecretLoadError):
        ClaudePIRProvider(model=model, api_key=key)


def test_inferred_provider_does_not_hide_sdk_failure(monkeypatch):
    from services.brain_service._lib_shim import default_pir_provider
    monkeypatch.setenv('CORELINE_ANTHROPIC_API_KEY', 'synthetic')
    monkeypatch.setitem(sys.modules, 'anthropic', None)
    with pytest.raises(SecretLoadError):
        default_pir_provider('model')
