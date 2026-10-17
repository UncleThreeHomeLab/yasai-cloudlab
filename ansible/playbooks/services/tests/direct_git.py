"""Exercise approved Git delivery and retained fixture retirement through existing owners."""
import copy
import json
import os
from pathlib import Path
import shlex
import time
from dotenv import dotenv_values
from playbooks.access.files.preflight import ssh
from playbooks.services.files.contract import ROOT
from playbooks.services.files.inputs import catalog
from playbooks.services.files import source
from playbooks.services.files.owners import Owners
from playbooks.services.files.lifecycle import publish, retire


def wait_backend(owner):
    end = time.monotonic() + 900
    while time.monotonic() < end:
        try:
            owner.backend_ready(owner.definition)
            return
        except RuntimeError:
            time.sleep(5)
    raise RuntimeError('Git deployment did not converge; preserve the scoped recovery checkpoint')


def run():
    os.umask(0o077)
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    current = catalog(required=True)
    checkpoint = Path('/recovery/direct-git-fixture.json')
    saved = json.loads(checkpoint.read_text()) if checkpoint.exists() else None
    original = saved['original'] if saved else current
    if current['dataApprovals'] != original['dataApprovals']:
        raise RuntimeError('Direct Git proof approvals changed; scoped resume refused')
    candidates = [row for row in original['catalog'] if row['approval']['repository'] == environment['PRIVATE_TEST_REPOSITORY']
                  and row['definition']['name'].startswith('fixture-') and row['publication'] == 'retired']
    if len(candidates) != 1:
        raise RuntimeError('Direct Git proof requires one already-approved retired private fixture')
    entry = candidates[0]
    from playbooks.data.files.service_proof import fixture
    fixture(entry)
    if entry['definition']['exposure']['class'] != 'private' or entry['definition']['oidc']['enabled']:
        raise RuntimeError('Direct Git proof cannot mutate public publication or human identity')
    import subprocess
    revision = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    public = __import__('yaml').safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
    origin = json.loads((ROOT / 'platform/connectivity/access/contract.json').read_text())['cloudflareOrigin']
    def owner(row):
        return Owners(dict(definition=row['definition'], approval=row['approval'],
                           platformRepository=public, platformRevision=revision, origin=origin, application=None))
    current_entry = next(row for row in current['catalog'] if row['approval']['name'] == entry['approval']['name'])
    restored = copy.deepcopy(current_entry)
    restored['publication'] = entry['publication']
    restored['definition']['environment'].pop('DIRECT_GIT_PROOF', None)
    if restored != entry or any(row not in current['catalog'] for row in original['catalog'] if row is not entry):
        raise RuntimeError('Direct Git input changed outside the owned fixture; resume refused')
    current_owner = owner(current_entry)
    current_owner.require_private_inputs(current_entry['definition'])
    before = saved['retained'] if saved else current_owner.read('fixture-snapshot')
    if current_owner.read('fixture-snapshot') != before:
        raise RuntimeError('Direct Git fixture identity changed; scoped resume refused')
    current_owner.read('fixture-data')
    if not saved:
        descriptor = os.open(checkpoint, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w') as stream:
            json.dump({'original': original, 'retained': before}, stream)
    proposed = copy.deepcopy(original)
    selected = next(row for row in proposed['catalog'] if row['approval']['name'] == entry['approval']['name'])
    selected['publication'] = 'ready'
    selected['definition'].setdefault('environment', {})['DIRECT_GIT_PROOF'] = 'approved-declaration'
    source.publish(proposed, expected=current)
    print(json.dumps({'approved_git_change_merged': True, 'local_catalog_apply': False}), flush=True)
    active = owner(selected)
    active.require_private_inputs(selected['definition'])
    wait_backend(active)
    print(json.dumps({'automatic_git_deployment_ready': True, 'pinned_source_verified': True}), flush=True)
    publish(selected['definition'], active)
    publish(selected['definition'], active)
    print(json.dumps({'private_publication_repeat': True, 'public_gateway_and_denied_identity_isolation': True}), flush=True)
    current, private_revision = catalog(required=True, coordinates=True)
    payload = {'repository': public, 'revision': revision, 'private_repository': environment['PRIVATE_CONFIG_REPOSITORY'],
               'private_revision': private_revision}
    script = (ROOT / 'ansible/playbooks/services/tests/source_outage.py').read_text()
    script = "import sys;sys.path.insert(0,'/opt/cloudlab');\n" + script + "\nprint(json.dumps(run(json.load(sys.stdin))))"
    result = json.loads(ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(script),
                           input=json.dumps(payload), timeout=1200))
    print(json.dumps(result), flush=True)
    retire(selected['definition'], active)
    after = active.read('fixture-snapshot')
    if before != after:
        raise RuntimeError('Direct Git retirement changed retained identities or scoped credentials')
    active.read('fixture-data'); active.read('fixture-volume')
    retired = catalog(required=True)
    source.publish(original, expected=retired)
    if catalog(required=True) != original:
        raise RuntimeError('Original retired catalog intent was not restored')
    _, final_revision = catalog(required=True, coordinates=True)
    payload['private_revision'] = final_revision
    check = "import sys,json;sys.path.insert(0,'/opt/cloudlab');from playbooks.istio.files.kube import wait;from playbooks.services.files.bootstrap import converged;p=json.load(sys.stdin);wait(lambda:converged(p),'final retired Git intent');print('{}')"
    ssh('VM', os.environ['VM_HOST'], 'python3 -c ' + shlex.quote(check), input=json.dumps(payload), timeout=660)
    checkpoint.unlink()
    return {'direct_git_delivery': True, 'no_new_application_module_or_command': True,
            'retired_intent_restored': True, 'retained_sql_s3_pvc_credentials': True,
            'local_catalog_apply': False, 'provider_apply': False, 'b2_calls': 0}


if __name__ == '__main__':
    print(json.dumps(run()), flush=True)
