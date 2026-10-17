"""Prepare disposable viewers through private Git inputs and the retained identity writer."""
import json
import os
import re
import secrets
import shlex
import time
from pathlib import Path
import yaml

from playbooks.secrets.files.vault import fields
from automation.identity.owner_enrollment import inputs
from automation.identity.operations import private_files
from automation.identity.private_source import publish
from automation.identity.session_fixture import membership, provision, local, scope


def environment(values):
    for key in ('VM_HOST', 'VM_USER', 'VM_PASSWORD', 'OP_SERVICE_ACCOUNT_TOKEN'):
        if not values.get(key): raise ValueError('Missing session prerequisite: ' + key)
        os.environ[key] = values[key]
    os.environ['VM_PORT'] = values.get('VM_PORT') or '22'


def prepare(checkpoint, realm):
    scope({'nonce': '0' * 32, 'realm': realm})
    values, api, source, revoked = inputs()
    environment(values)
    if checkpoint.exists():
        request = json.loads(checkpoint.read_text())
        scope(request)
        if request.get('realm') != realm: raise ValueError('Session checkpoint has another realm')
    else:
        request = {'nonce': secrets.token_hex(16), 'realm': realm}
        from playbooks.data.files.control import atomic
        atomic(checkpoint, request)
    provision(request)
    try:
        local(request, stage=True)
    except RuntimeError:
        # Interrupted enrollment may already own the account; native guards verify it.
        from playbooks.argocd.files.github_setup import repository
        repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
        wait_private_source(api.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha'])
        local(request)
        return {'disposable_viewer_ready': True, 'primary_users_changed': False}
    from playbooks.argocd.files.github_setup import repository
    from automation.identity.private_source import decode_contents
    repo = repository(values['PRIVATE_CONFIG_REPOSITORY'])
    prefix = 'repos/' + repo
    base = api.request('GET', prefix + '/git/ref/heads/main')['object']['sha']
    current = yaml.safe_load(decode_contents(api.request('GET', prefix + '/contents/identity/configmap.yaml?ref=' + base)))
    if json.loads(current['data']['desired_state']) != source or json.loads(current['data']['revocations']) != revoked:
        raise RuntimeError('Private identity inventory advanced; reread before publishing the viewer')
    credentials = fields('keycloak-proof-' + request['nonce'], ('username', 'password', 'email', 'ownership_id'))
    source = membership(source, revoked, credentials, request)
    client_secrets = json.loads(fields('keycloak-client-secrets', ('client_secrets',))['client_secrets'])
    # Existing callback producers retain their validated issuer; this call only checks syntax.
    prepared = private_files(source, revoked, client_secrets, 'validation.invalid')
    result = publish(api, values, prepared)
    if result['private_source_changed']:
        pull = api.request('GET', 'repos/' + repo + '/pulls/' + str(result['private_pull_request']))
        files = api.request('GET', prefix + '/pulls/' + str(pull['number']) + '/files')
        if (pull['base']['sha'] != base or len(files) != 1 or files[0]['filename'] != 'identity/configmap.yaml' or
                files[0]['status'] != 'modified' or api.request('GET', prefix + '/git/ref/heads/main')['object']['sha'] != base or
                decode_contents(api.request('GET', prefix + '/contents/identity/configmap.yaml?ref=' + pull['head']['sha'])) !=
                prepared['identity/configmap.yaml'].encode()):
            raise RuntimeError('Private disposable membership review changed; merge refused')
        merged = api.request('PUT', 'repos/' + repo + '/pulls/' + str(pull['number']) + '/merge',
                             {'sha': pull['head']['sha'], 'merge_method': 'squash'})
        if not merged.get('merged'): raise RuntimeError('Protected disposable membership merge incomplete')
        revision = merged['sha']
    else:
        revision = api.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
    wait_private_source(revision)
    local(request)
    return {'disposable_viewer_ready': True, 'primary_users_changed': False}


def wait_private_source(revision):
    if not isinstance(revision, str) or not re.fullmatch('[a-f0-9]{40}', revision):
        raise ValueError('Disposable enrollment requires an immutable private revision')
    from playbooks.access.files.preflight import ssh
    script = """import sys,json
sys.path.insert(0,'/opt/cloudlab')
from playbooks.istio.files.kube import application_ready,wait
revision=json.load(sys.stdin)['revision']
wait(lambda:application_ready('cloudlab-identity-private',revision),'private fixture source convergence',timeout=600)
print(json.dumps({'private_source_ready':True}))
"""
    ready = json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(script),
                          input=json.dumps({'revision': revision}), timeout=630))
    if ready != {'private_source_ready': True}:
        raise RuntimeError('Private fixture source convergence incomplete')


def retire(api, values, request, checkpoint):
    scope(request)
    from automation.identity.session_acceptance import offboard_inputs, remote_state
    from automation.identity.lifecycle import local_offboard
    identity = remote_state(request)
    offboard_inputs(api, values, request, resume=True)
    limit = json.loads((Path(__file__).resolve().parents[2] / 'platform/identity/keycloak/contract.json').read_text())['sessions']['private_revocation_convergence_seconds']
    deadline = time.monotonic() + limit
    current = identity
    while current['enabled'] is not False:
        if time.monotonic() >= deadline:
            raise RuntimeError('Disposable viewer offboarding convergence deadline exceeded')
        time.sleep(5)
        current = remote_state(request)
        if any(current[key] != identity[key] for key in ('realm', 'username', 'user_id', 'email', 'preservation')):
            raise RuntimeError('Disposable identity or unrelated users changed during offboarding')
    local_offboard({key: identity[key] for key in ('realm', 'username', 'user_id', 'email')})
    checkpoint.unlink()
