"""Explicit, journaled preview preactivation/viewer/PR stages; never a default lab action."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess

from dotenv import dotenv_values

from playbooks.previews.tests import catalog_fixture as fixture
from playbooks.keycloak.tests import scoped_session as session
from playbooks.previews.files.contract import digest

ROOT = Path(__file__).resolve().parents[4]
ACTIONS = ('inspect', 'viewer-provision', 'viewer-stage', 'viewer-propose', 'viewer-merge', 'viewer-enroll',
           'viewer-observe', 'offboard-propose', 'offboard-merge', 'viewer-offboard', 'pr-create', 'pr-advance', 'pr-cleanup', 'browser',
           'approval-prepare', 'approval-abandon', 'catalog-prepare', 'catalog-reprepare', 'catalog-propose', 'catalog-review', 'catalog-merge', 'catalog-retire', 'lifecycle-observe',
           'custody-install', 'custody-observe', 'probe-prepare', 'probe-observe', 'probe-cleanup', 'retained-create', 'retained-observe', 'retained-delete',
           'outage-prepare', 'outage-observe', 'outage-fault', 'outage-restore', 'outage-cleanup')


class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise ValueError('Invalid fixture arguments; values withheld')


def resource_remote(values, request):
    from playbooks.previews.files.command import vm_environment
    from playbooks.previews.tests.resource_runtime import validate
    validate(request)
    vm_environment(values)
    environment = dict(os.environ, CLOUDLAB_PREVIEW_RESOURCE_REQUEST=json.dumps(request))
    result = subprocess.run(['ansible-playbook', '-i', 'inventory.yml', 'playbooks/previews/tests/resources.yml'],
        cwd=ROOT / 'ansible', env=environment, capture_output=True, timeout=900)
    if result.returncode:
        raise RuntimeError('Preview resource Ansible operation failed; diagnostics withheld')
    target = fixture.JOURNALS / request['nonce'] / 'resource-result.json'
    if target.is_symlink() or target.stat().st_size > 32768 or target.stat().st_mode & 0o077:
        raise ValueError('Resource result is not private and bounded')
    return json.loads(target.read_text())


def resource_request(action, state):
    from playbooks.previews.tests.resource_runtime import validate
    slots = ('a', 'b') if action.startswith('probe-') else ('d',) if action.startswith('retained-') else ()
    rows = [state.get('approvals', {}).get(slot, {}).get('row') for slot in slots]
    if any(row is None for row in rows):
        raise ValueError('Runtime fixture requires the exact journal-owned approval slots')
    request = {'action': action, 'nonce': state['nonce'], 'revision': state['executionPlatform'], 'rows': rows}
    validate(request)
    return request


def host_readiness(values, state):
    from playbooks.previews.files.command import vm_environment
    from playbooks.previews.tests.probe_transport import handoff
    vm_environment(values)
    if handoff(state, [], [], host_only=True) != {'host': True}:
        raise ValueError('Private host custody is not ready')


def remote(values, request):
    from playbooks.previews.files.command import vm_environment
    from playbooks.previews.tests.viewer_runtime import validate
    validate(request)
    vm_environment(values)
    environment = dict(os.environ, CLOUDLAB_PREVIEW_VIEWER_REQUEST=json.dumps(request))
    result = subprocess.run(['ansible-playbook', '-i', 'inventory.yml', 'playbooks/previews/tests/viewer.yml'],
        cwd=ROOT / 'ansible', env=environment, capture_output=True, timeout=2600)
    if result.returncode:
        raise RuntimeError('Preview fixture Ansible operation failed; private diagnostics withheld')
    path = fixture.JOURNALS / request['nonce'] / 'viewer-result.json'
    if path.is_symlink() or path.stat().st_size > 1048576 or path.stat().st_mode & 0o077:
        raise ValueError('Preview fixture observation is not private and bounded')
    return json.loads(path.read_text())


def publication(api, values, state, save, *, offboard=False):
    key = 'offboarding' if offboard else 'membership'
    if key not in state:
        snapshot = session.inspect(api, values)
        prepared = session.prepare(snapshot, state['viewer'], offboard=offboard)
        state[key] = {'snapshot': snapshot, 'prepared': prepared}
        save()
    record = state[key]
    from playbooks.previews.tests.approval_fixture import Publication
    from playbooks.argocd.files.github_setup import repository
    wrapped = Publication(api, repository(values['PRIVATE_CONFIG_REPOSITORY']), record, save,
        'identity', record['prepared'], record['snapshot']['revision'])
    result = session.propose(wrapped, values, record['snapshot'], record['prepared'])
    if result['private_source_changed']:
        number = result['private_pull_request']
        from playbooks.argocd.files.github_setup import repository
        pull = api.request('GET', 'repos/' + repository(values['PRIVATE_CONFIG_REPOSITORY']) + '/pulls/' + str(number))
        record.update(number=number, head=pull['head']['sha'])
        session.review(api, values, record['snapshot'], record['prepared'], record['number'], record['head'])
    else:
        record['revision'] = result['private_revision']
    save()


def publication_merge(api, values, state, save, *, offboard=False):
    record = state['offboarding' if offboard else 'membership']
    if 'revision' not in record:
        record['revision'] = session.merge(api, values, record['snapshot'], record['prepared'], record['number'], record['head'])
        save()


def prerequisites(action, state, slot, *, batch='ab', lifetime=3000, mode='approve'):
    if action != 'inspect' and 'baseline' not in state:
        raise ValueError('Inspect and journal the private/cluster baseline first')
    if action.startswith('custody-') and (slot is not None or not state.get('enrolled') or 'offboarding' in state):
        raise ValueError('Custody preparation requires the enrolled owned viewer and no PR slot')
    if action.startswith(('probe-', 'retained-', 'outage-')):
        if slot is not None:
            raise ValueError('Runtime fixture actions do not accept a PR slot')
        resource_request(action, state)
    if state.get('abandonedPreparation'):
        permitted = ('inspect', 'approval-abandon', 'viewer-observe', 'lifecycle-observe', 'offboard-propose',
                     'offboard-merge', 'viewer-offboard', 'pr-cleanup', 'catalog-retire',
                     'probe-observe', 'probe-cleanup', 'retained-observe', 'retained-delete', 'outage-observe', 'outage-restore', 'outage-cleanup')
        if action.startswith('catalog-') and action != 'catalog-retire':
            from playbooks.previews.tests.approval_fixture import current
            reducing = (mode if action == 'catalog-prepare' else current(state)['mode']) in ('withdraw', 'orphan-d', 'cleanup', 'finalize')
        else:
            reducing = False
        if action not in permitted and not reducing:
            raise ValueError('Abandoned preparation permits only observation and authority-reducing cleanup')
    if action == 'approval-prepare':
        if (batch not in ('ab', 'cd') or type(lifetime) is not int or not 60 <= lifetime <= 3000 or
                not state.get('enrolled') or 'offboarding' in state or any(
                    not state.get('pulls', {}).get(value, {}).get('head') for value in batch)):
            raise ValueError('Prepare only the exact enrolled owned PR pair and bounded lifetime')
    if action.startswith('catalog-'):
        from playbooks.previews.tests.approval_fixture import current, MODES, orphan_rows
        if slot is not None:
            raise ValueError('Catalog transitions do not accept a PR slot')
        if action == 'catalog-prepare':
            if batch not in ('ab', 'cd') or mode not in MODES:
                raise ValueError('Catalog transition requires a fixed batch and mode')
            if mode != 'finalize' and any('row' not in state.get('approvals', {}).get(value, {}) for value in batch):
                raise ValueError('Prepare the exact owned approval pair first')
            if mode == 'orphan-d':
                orphan_rows(state, batch)
        elif action != 'catalog-retire':
            record = current(state)
            if record['mode'] == 'orphan-d':
                orphan_rows(state, record['batch'])
    if action == 'lifecycle-observe' and not state.get('approvals'):
        raise ValueError('Prepare owned approvals before lifecycle observation')
    if action == 'browser' and (not state.get('enrolled') or 'offboarding' in state or
            not isinstance(state.get('browserApprovals'), dict) or set(state['browserApprovals']) != {'a', 'b'}):
        raise ValueError('Browser proof requires its enrolled viewer and explicit A/B approval receipts')
    if action == 'browser' and state.get('browserAttempted'):
        raise ValueError('Browser attempt cannot reset its ephemeral authenticator; retain ownership and offboard')
    if action in ('viewer-stage', 'viewer-propose', 'offboard-propose') and not state.get('provisioned'):
        raise ValueError('Provision the journal-owned viewer first')
    if action in ('viewer-propose', 'offboard-propose') and not state.get('staged'):
        raise ValueError('Stage the journal-owned viewer before publication')
    if action in ('offboard-propose', 'viewer-observe', 'viewer-offboard') and not state.get('enrolled'):
        raise ValueError('Enroll the journal-owned viewer first')
    if action in ('viewer-merge', 'viewer-enroll') and 'membership' not in state:
        raise ValueError('Propose the viewer membership first')
    if action in ('viewer-merge', 'offboard-merge'):
        record = state.get('membership' if action == 'viewer-merge' else 'offboarding', {})
        if 'revision' not in record and (type(record.get('number')) is not int or
                not isinstance(record.get('head'), str) or not re.fullmatch('[a-f0-9]{40}', record['head'])):
            raise ValueError('Review the exact proposed viewer PR and head first')
    if action == 'viewer-enroll' and ('revision' not in state['membership'] or 'offboarding' in state):
        raise ValueError('Merge the active viewer membership before enrollment')
    if action in ('offboard-merge', 'viewer-offboard') and 'offboarding' not in state:
        raise ValueError('Propose the persistent viewer tombstone first')
    if action == 'viewer-offboard' and 'revision' not in state['offboarding']:
        raise ValueError('Merge the persistent viewer tombstone before runtime offboarding')
    if action in ('viewer-provision', 'viewer-stage', 'viewer-propose', 'viewer-merge') and 'offboarding' in state:
        raise ValueError('Offboarding viewers cannot be reactivated')
    if action.startswith('pr-'):
        if slot not in ('a', 'b', 'c', 'd') or not state.get('enrolled'):
            raise ValueError('Fixture PR stages require their enrolled viewer and bounded slot')
        if action != 'pr-create' and slot not in state['pulls']:
            raise ValueError('Fixture PR has no creation journal')
        receipt = state['pulls'].get(slot)
        if receipt and action != 'pr-cleanup' and (receipt.get('closed') or receipt.get('deleted')):
            raise ValueError('Closed fixture PRs cannot be reactivated')
        if action == 'pr-advance' and receipt.get('number') is None:
            raise ValueError('Create the fixture PR before advancing its branch')


def execution_source(state, revision):
    original = state.get('platform')
    if not isinstance(original, str) or not re.fullmatch('[a-f0-9]{40}', original):
        raise ValueError('Fixture journal platform provenance is invalid')
    if original != revision and subprocess.run(['git', 'merge-base', '--is-ancestor', original, revision],
            cwd=ROOT, capture_output=True, timeout=30).returncode:
        raise ValueError('Fixture journal belongs to an unrelated platform history')
    state['executionPlatform'] = revision


def execute(action, values, state, save, slot=None, *, batch='ab', lifetime=3000, mode='approve'):
    request = state['viewer']
    prerequisites(action, state, slot, batch=batch, lifetime=lifetime, mode=mode)
    if action == 'approval-abandon':
        from playbooks.previews.tests.approval_fixture import abandon_preparation
        abandon_preparation(state, save)
        return
    intent = {'action': action, 'slot': slot}
    if action == 'approval-prepare':
        intent.update(batch=batch, lifetime=lifetime)
    if action == 'catalog-prepare':
        intent.update(batch=batch, mode=mode)
    stale_catalog = False
    if action == 'catalog-reprepare' and state.get('intent') in (
            {'action': name, 'slot': None} for name in ('catalog-propose', 'catalog-review', 'catalog-merge')):
        from playbooks.previews.tests.approval_fixture import reprepare_check
        with session.private_context(values) as api:
            reprepare_check(api, values, state)
        stale_catalog = True
    interrupted_browser = (action == 'offboard-propose' and slot is None and
        state.get('browserAttempted') is True and state.get('intent') == {'action': 'browser', 'slot': None})
    resource_recovery = {'probe-cleanup': ('probe-prepare', 'probe-observe'),
        'retained-delete': ('retained-create', 'retained-observe'),
        'outage-restore': ('outage-prepare', 'outage-observe', 'outage-fault'),
        'outage-cleanup': ('outage-prepare', 'outage-observe', 'outage-restore')}
    reducing_resource = slot is None and state.get('intent') in (
        {'action': previous, 'slot': None} for previous in resource_recovery.get(action, ()))
    if state.get('intent') not in (None, intent) and not interrupted_browser and not stale_catalog and not reducing_resource:
        raise ValueError('Resume the journaled operation before beginning another fixture stage')
    if interrupted_browser:
        state['browserFailed'] = True
    completed = {'viewer-provision': 'provisioned', 'viewer-stage': 'staged',
                 'viewer-enroll': 'enrolled', 'viewer-offboard': 'offboarded'}.get(action)
    publication_key = {'viewer-propose': 'membership', 'viewer-merge': 'membership',
                       'offboard-propose': 'offboarding', 'offboard-merge': 'offboarding'}.get(action)
    if (completed and state.get(completed)) or (publication_key and 'revision' in state.get(publication_key, {})):
        state['intent'] = None
        save()
        return
    state['intent'] = intent
    save()
    if action == 'inspect':
        from playbooks.argocd.files.github_setup import repository
        with session.private_context(values) as api:
            inspected = fixture.inspect(api, repository(values['PRIVATE_CONFIG_REPOSITORY']))
            if inspected['catalog'] is not None:
                fixture.require_fixture_only(inspected['catalog'], state.get('instances', []))
            identity = session.inspect(api, values)
        observed = remote(values, dict(request, action='baseline', instances=state.get('instances', [])))
        if 'baseline' not in state:
            state['baseline'] = {'catalog': inspected, 'identity': identity, 'cluster': observed}
        state['inspection'] = {'catalog': inspected, 'identity': identity, 'cluster': observed}
    elif action == 'approval-prepare':
        from playbooks.previews.tests.approval_fixture import prepare
        observed = remote(values, dict(request, action='observe'))
        if observed != state.get('identity') or observed.get('enabled') is not True:
            raise ValueError('Fresh enrolled viewer identity changed before approval preparation')
        remote(values, dict(request, action='lifecycle', approvals=[], expected={}, revision=state['executionPlatform']))
        host_readiness(values, state)
        prepare(values, state, save, batch, lifetime)
    elif action == 'custody-install':
        if resource_remote(values, resource_request(action, state)) != {'installed': True}:
            raise ValueError('Custody installation did not complete')
    elif action == 'custody-observe':
        host_readiness(values, state)
    elif action.startswith('catalog-'):
        from playbooks.previews.tests import approval_fixture as approval
        removing = (action == 'catalog-retire' or
                    (action == 'catalog-prepare' and mode in ('cleanup', 'finalize')) or
                    (action in ('catalog-propose', 'catalog-review', 'catalog-merge', 'catalog-reprepare') and
                     approval.current(state)['mode'] in ('cleanup', 'finalize')))
        if removing and approval.rows(state):
            observed = remote(values, dict(request, action='lifecycle', approvals=list(approval.rows(state).values()),
                expected=state.get('evidence', {}), revision=state['executionPlatform']))
            approval.remember(state, observed, save)
            if any(not (value.get('cleanupOnlyAbsent') or value.get('absent')) for value in observed['entries'].values()):
                raise ValueError('Fresh execution and client absence is required for catalog cleanup')
        operations = {'catalog-prepare': lambda api: approval.catalog_prepare(api, values, state, save, batch, mode),
            'catalog-reprepare': lambda api: approval.reprepare(api, values, state, save),
            'catalog-propose': lambda api: approval.propose(api, values, state, save),
            'catalog-review': lambda api: approval.review(api, values, state, save),
            'catalog-merge': lambda api: approval.merge(api, values, state, save),
            'catalog-retire': lambda api: approval.retire_proposals(api, values, state, save)}
        with session.private_context(values, write=action in ('catalog-propose', 'catalog-merge', 'catalog-retire')) as api:
            operations[action](api)
    elif action == 'lifecycle-observe':
        from playbooks.previews.tests import approval_fixture as approval
        observed = remote(values, dict(request, action='lifecycle', approvals=list(approval.rows(state).values()), expected=state.get('evidence', {}), revision=state['executionPlatform']))
        approval.remember(state, observed, save)
        baseline = remote(values, dict(request, action='baseline', instances=state.get('instances', [])))
        approval.preserve_baseline(state, baseline)
    elif action.startswith(('probe-', 'retained-', 'outage-')):
        from playbooks.previews.tests.approval_fixture import preserve_baseline
        observed = resource_remote(values, resource_request(action, state))
        state.setdefault('resourceEvidence', {})[action] = observed
        save()
        preserve_baseline(state, remote(values, dict(request, action='baseline', instances=state.get('instances', []))))
    elif action == 'viewer-provision':
        from playbooks.keycloak.files.session_fixture import provision
        provision(request)
        state['provisioned'] = True
    elif action == 'viewer-stage':
        if not state.get('provisioned'):
            raise ValueError('Provision only the journal-owned viewer before staging')
        remote(values, dict(request, action='stage'))
        state['staged'] = True
    elif action in ('viewer-propose', 'offboard-propose'):
        if not state.get('staged') or (action == 'offboard-propose' and not state.get('enrolled')):
            raise ValueError('Viewer source publication requires its staged/enrolled receipt')
        with session.private_context(values, write=True) as api:
            publication(api, values, state, save, offboard=action == 'offboard-propose')
    elif action in ('viewer-merge', 'offboard-merge'):
        with session.private_context(values, write=True) as api:
            publication_merge(api, values, state, save, offboard=action == 'offboard-merge')
    elif action == 'viewer-enroll':
        if 'offboarding' in state:
            raise ValueError('Offboarding viewer cannot be reactivated')
        remote(values, dict(request, action='wait', revision=state['membership']['revision']))
        remote(values, dict(request, action='enroll'))
        state['identity'] = remote(values, dict(request, action='observe'))
        state['enrolled'] = True
    elif action == 'viewer-observe':
        observed = remote(values, dict(request, action='observe'))
        if state.get('identity') and any(observed[key] != state['identity'][key] for key in ('realm', 'username', 'user_id', 'email')):
            raise ValueError('Viewer identity changed since its journal receipt')
        state['identity'] = observed
    elif action == 'browser':
        from playbooks.previews.tests.browser_live import run
        def begin_enrollment():
            state['browserAttempted'] = True
            save()
        try:
            state['browserProof'] = run(values, state, remote, begin_enrollment)
        except Exception:
            # Only the durable begin marker consumes MFA; earlier refusals remain retryable.
            state['browserFailed'] = True
            if state['intent'] == intent:
                state['intent'] = None
            save()
            raise
    elif action == 'viewer-offboard':
        remote(values, dict(request, action='wait', revision=state['offboarding']['revision']))
        identity = {key: state['identity'][key] for key in ('realm', 'username', 'user_id', 'email')}
        remote(values, dict(request, action='offboard', identity=identity))
        state['offboarded'] = True
    else:
        from playbooks.argocd.files.github_setup import repository
        if slot not in ('a', 'b', 'c', 'd') or not state.get('enrolled'):
            raise ValueError('Fixture PR stages require their enrolled viewer and bounded slot')
        with session.private_context(values, write=True) as api:
            if slot not in state['pulls']:
                if action != 'pr-create':
                    raise ValueError('Fixture PR has no creation journal')
                state['pulls'][slot] = fixture.pull_receipt(api, repository(values['PRIVATE_CONFIG_REPOSITORY']), request['nonce'], slot)
                save()
            receipt = state['pulls'][slot]
            if action == 'pr-create':
                fixture.commit_pull(api, receipt, request['nonce'], slot, save)
                fixture.open_pull(api, receipt, request['nonce'], slot, save)
            elif action == 'pr-advance':
                if receipt['generation'] < 1:
                    fixture.commit_pull(api, receipt, request['nonce'], slot, save, advance=True)
            else:
                fixture.cleanup_pull(api, receipt, request['nonce'], slot, save)
    state['intent'] = None
    save()


def main(arguments=None):
    parser = Parser(description=__doc__)
    parser.add_argument('action', choices=ACTIONS)
    parser.add_argument('--nonce', required=True)
    parser.add_argument('--slot', choices=('a', 'b', 'c', 'd'))
    parser.add_argument('--batch', choices=('ab', 'cd'), default='ab')
    parser.add_argument('--lifetime', type=int, default=3000)
    from playbooks.previews.tests.approval_fixture import MODES
    parser.add_argument('--mode', choices=MODES, default='approve')
    parser.add_argument('--live', action='store_true')
    args = parser.parse_args(arguments)
    if not args.live or not re.fullmatch('[a-f0-9]{32}', args.nonce):
        raise ValueError('Explicit live opt-in and journal nonce required')
    from playbooks.argocd.files.render import committed_payload
    platform = committed_payload()
    path = fixture.JOURNALS / args.nonce / 'journal.json'
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Fixture journal has conflicting filesystem ownership')
    if not path.exists():
        fixture.journal(path, {'format': 1, 'nonce': args.nonce, 'platform': platform['revision'],
            'viewer': {'nonce': args.nonce, 'realm': 'applications'}, 'pulls': {}, 'intent': None})
    lock = os.open(path.parent / 'operation.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        raw = path.read_bytes()
        if len(raw) > 4194304 or path.stat().st_mode & 0o077:
            raise ValueError('Fixture journal is not private and bounded')
        state = json.loads(raw)
        if (state.get('format') != 1 or state.get('nonce') != args.nonce or
                state.get('viewer') != {'nonce': args.nonce, 'realm': 'applications'}):
            raise ValueError('Fixture journal source or ownership changed')
        expected = digest(raw)
        def save():
            nonlocal expected
            expected = fixture.journal(path, state, expected=expected)
        execution_source(state, platform['revision'])
        values = dotenv_values(ROOT / '.env', interpolate=False)
        os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
        execute(args.action, values, state, save, args.slot, batch=args.batch, lifetime=args.lifetime, mode=args.mode)
    finally:
        os.close(lock)
    print(json.dumps({'fixture_stage_completed': True, 'live_acceptance_complete': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Preview fixture stage failed; retain its private journal; diagnostics withheld') from None
