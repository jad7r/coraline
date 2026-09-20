"""Post-commit failure injection against real core records and CLI exit codes."""
import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from core.incident.workspace import IncidentWorkspace
from interfaces.cli.coreline import app


def run(home, *args):
    return CliRunner().invoke(app, list(args), env={'CORELINE_HOME': str(home), 'CORELINE_ACTOR': 'tester'})


@pytest.fixture
def workspace(tmp_path):
    ws = IncidentWorkspace.declare(tmp_path / 'incidents', title='Audit', severity='SEV2', actor='tester')
    assert run(ws.home, 'registry', 'init').exit_code == 0
    assert run(ws.home, 'registry', 'trust-active').exit_code == 0
    return ws


def snapshot(root):
    return {str(p.relative_to(root)): (p.read_bytes(), p.stat().st_mtime_ns)
            for p in root.rglob('*') if p.is_file()}


@pytest.mark.parametrize('kind', ['subjects', 'observations', 'claims', 'actions', 'decisions'])
def test_record_tampering_fails_plain_trusted_and_doctor(workspace, kind):
    ws = workspace
    subject = ws.create_subject('HOST', 'original', 'tester')
    obs = ws.add_observation('original', 'tester', subject_refs=[subject.subject_id])
    claim = ws.add_claim('original', 'tester', observation_refs=[obs.observation_id])
    action = ws.create_action('contain', 'original', 'tester', claim_refs=[claim.claim_id])
    ws.create_decision('review', 'original', 'reason', 'human', 'tester', action_refs=[action.action_id])
    path = ws.dir / f'{kind}.json'
    path.write_text(path.read_text().replace('original', 'tampered'))
    before = snapshot(ws.home)
    assert ws.verify()[kind] is False
    assert ws.verify()['ok'] is False
    for args in [('verify',), ('verify', '--trusted'), ('doctor',)]:
        result = run(ws.home, *args)
        assert result.exit_code == 1
        assert isinstance(result.exception, SystemExit)
    assert snapshot(ws.home) == before


@pytest.mark.parametrize('damage', ['missing', 'empty', 'json', 'shape', 'last', 'sequence', 'stored_hash', 'null_hash'])
def test_audit_damage_fails_closed_without_writes(workspace, damage):
    ws = workspace
    if damage == 'missing':
        ws._audit_path.unlink()
    elif damage in ('empty', 'json', 'shape'):
        ws._audit_path.write_text({'empty': '', 'json': '{', 'shape': '[]'}[damage])
    else:
        entries = [json.loads(line) for line in ws._audit_path.read_text().splitlines()]
        if damage == 'last':
            entries[-1]['actor'] = 'tampered'
        elif damage == 'sequence':
            entries[-1]['seq'] = 91
        elif damage == 'null_hash':
            entries[-1]['actor'] = 'tampered'
            entries[-1]['entry_hash'] = None
        else:
            entries[-1]['entry_hash'] = '0' * 64
        ws._audit_path.write_text('\n'.join(json.dumps(e) for e in entries) + '\n')
    before = snapshot(ws.home)
    assert not ws.verify()['audit_chain']
    for args in [('verify',), ('verify', '--trusted'), ('doctor',)]:
        result = run(ws.home, *args)
        assert result.exit_code == 1
        assert isinstance(result.exception, SystemExit)
    assert snapshot(ws.home) == before


@pytest.mark.parametrize('damage', ['missing', 'json', 'list', 'status'])
def test_malformed_state_has_controlled_exit(workspace, damage):
    ws = workspace
    if damage == 'missing':
        ws._state_path.unlink()
    else:
        value = {'json': '{', 'list': '[]', 'status': json.dumps({'incident_id': ws.incident_id, 'status': 'garbage'})}[damage]
        ws._state_path.write_text(value)
    before = snapshot(ws.home)
    for args in [('verify',), ('verify', '--all'), ('verify', '--trusted', '--all'), ('doctor',)]:
        result = run(ws.home, *args)
        assert result.exit_code == 1
        assert isinstance(result.exception, SystemExit)
    assert snapshot(ws.home) == before


@pytest.mark.parametrize('filename', ['signer.json', 'manifest.sig', 'manifest.json'])
def test_malformed_trust_artifacts_fail(workspace, filename):
    (workspace.dir / filename).write_text('malformed')
    result = run(workspace.home, 'verify', '--trusted')
    assert result.exit_code == 1


def test_sealed_verification_is_deterministic_and_read_only(workspace, tmp_path):
    evidence = tmp_path / 'evidence.txt'
    evidence.write_text('preserved evidence')
    workspace.add_evidence(str(evidence), note='test', actor='tester')
    workspace.close_incident('tester')
    workspace.seal_incident('tester')
    before = snapshot(workspace.home)
    first = run(workspace.home, 'verify', '--trusted', '--min-sequence', '2')
    second = run(workspace.home, 'verify', '--trusted', '--min-sequence', '2')
    assert first.exit_code == second.exit_code == 0
    assert first.output == second.output
    assert snapshot(workspace.home) == before


def test_registry_error_does_not_echo_untrusted_values(workspace):
    canary = 'CORELINE_TEST_SECRET_DO_NOT_LOG_7f3a91'
    registry = workspace.home / 'trust' / 'registry.json'
    data = json.loads(registry.read_text())
    data['signers'][0]['status'] = canary
    registry.write_text(json.dumps(data))
    result = run(workspace.home, 'verify', '--trusted')
    assert result.exit_code == 1
    assert canary not in result.output


def test_empty_store_does_not_claim_verified_incidents(tmp_path):
    result = run(tmp_path, 'verify', '--all')
    assert result.exit_code == 0
    assert 'no incidents' in result.output
    assert 'verification passed' not in result.output
