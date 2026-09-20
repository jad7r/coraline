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


@pytest.mark.asyncio
@pytest.mark.parametrize('namespace', ['Coreline', 'secops-secure-enclave'])
async def test_brain_ready_with_keychain_only_credentials(credentials, namespace):
    for name in ('ANTHROPIC_API_KEY', 'SLACK_BOT_TOKEN', 'JIRA_API_TOKEN', 'JIRA_EMAIL'):
        key = name.lower() if namespace == 'Coreline' else 'CORELINE_' + name
        credentials[namespace, key] = 'test-value'
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=AsyncMock())))
    assert await readiness_check(request) == {
        'status': 'ready', 'checks': {'redis': True, 'credentials': True}}
    credentials.clear()
    with pytest.raises(HTTPException) as error:
        await readiness_check(request)
    assert error.value.status_code == 503
    assert error.value.detail['checks'] == {'redis': True, 'credentials': False}


@pytest.mark.asyncio
async def test_brain_ready_fails_when_redis_is_down(monkeypatch):
    import redis.exceptions
    for name in ('ANTHROPIC_API_KEY', 'SLACK_BOT_TOKEN', 'JIRA_API_TOKEN', 'JIRA_EMAIL'):
        monkeypatch.setenv('CORELINE_' + name, 'test-value')
    client = AsyncMock()
    client.ping.side_effect = redis.exceptions.ConnectionError('offline')
    request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(redis=client)))
    with pytest.raises(HTTPException) as error:
        await readiness_check(request)
    assert error.value.status_code == 503
    assert error.value.detail['checks'] == {'redis': False, 'credentials': True}


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
