"""Explicit recovery of one recorded fixture-created sources-only Update owner."""
import copy
import fcntl
import json
from pathlib import Path
import re
import sys

sys.path.insert(0, '/opt/cloudlab')
from playbooks.istio.files.kube import contains, get, kube, wait
from playbooks.services.files.bootstrap import APP, OWNER, application, converged


def source_entries(app):
    return [row for row in app['metadata'].get('managedFields', [])
            if 'f:sources' in row.get('fieldsV1', {}).get('f:spec', {})]


def stable_metadata(app):
    return {key: value for key, value in app['metadata'].items()
            if key not in ('resourceVersion', 'generation', 'managedFields')}


def recover(payload, record):
    if (set(record) != {'uid', 'sources', 'entry'} or not isinstance(record['entry'], dict)
            or set(record['entry']) != {'apiVersion', 'fieldsType', 'fieldsV1', 'manager', 'operation', 'time'}
            or record['entry']['manager'] != OWNER or record['entry']['operation'] != 'Update'
            or record['entry']['apiVersion'] != 'argoproj.io/v1alpha1'
            or record['entry']['fieldsType'] != 'FieldsV1'
            or record['entry']['fieldsV1'] != {'f:spec': {'f:sources': {}}}
            or not re.fullmatch(r'\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ', record['entry']['time'])):
        raise ValueError('Recovery requires the exact recorded sources-only Update entry')
    desired = application(payload)
    with Path('/run/lock/cloudlab-services.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = get('application.argoproj.io', APP, 'argocd')
        if (not current or current['metadata']['uid'] != record['uid']
                or current['metadata'].get('labels', {}).get('cloudlab.io/owner') != OWNER
                or current['metadata'].get('ownerReferences') or current['metadata'].get('finalizers')
                or current['metadata'].get('deletionTimestamp')):
            raise RuntimeError('Source recovery refuses a different Application identity or owner')
        entries = source_entries(current)
        if (len(entries) == 1 and entries[0]['manager'] == OWNER and entries[0]['operation'] == 'Apply'
                and contains(current, desired)):
            wait(lambda: converged(payload), 'recovered service catalog convergence', timeout=600)
            return {'changed': False}
        if entries != [record['entry']] or current['spec']['sources'] != record['sources']:
            raise RuntimeError('Source recovery refuses changed sources or field ownership')
        before = copy.deepcopy(payload)
        before['revision'] = record['sources'][0]['targetRevision']
        if not converged(before):
            raise RuntimeError('Source recovery requires the exact healthy idle catalog')
        expected = copy.deepcopy(current['spec'])
        expected['sources'][0]['targetRevision'] = payload['revision']
        expected['sources'][0]['helm']['valuesObject']['revision'] = payload['revision']
        if (not re.fullmatch(r'[0-9a-f]{40}', payload['revision'])
                or payload['revision'] == before['revision'] or expected != desired['spec']):
            raise RuntimeError('Source recovery permits only an approved public revision change')
        desired['metadata'].update(uid=record['uid'], resourceVersion=current['metadata']['resourceVersion'])
        arguments = ('apply', '--server-side', '--field-manager=' + OWNER, '-f', '-')
        refusal = kube(*arguments, '--dry-run=server', document=desired, allow_failure=True)
        conflict = 'Apply failed with 1 conflict: conflict with "' + OWNER + '" using argoproj.io/v1alpha1: .spec.sources'
        if refusal.returncode == 0 or refusal.stderr.count('conflict with ') != 1 or conflict not in refusal.stderr:
            raise RuntimeError('Source recovery requires only the recorded sources conflict')
        probe = json.loads(kube(*arguments, '--force-conflicts', '--dry-run=server',
                                '-o', 'json', '--show-managed-fields=true', document=desired))
        owners = source_entries(probe)
        previous_apply = [row for row in current['metadata']['managedFields']
                          if row.get('manager') == OWNER and row.get('operation') == 'Apply']
        foreign = lambda app: [row for row in app['metadata']['managedFields']
                               if row != record['entry'] and not (row.get('manager') == OWNER
                                   and row.get('operation') == 'Apply' and row.get('apiVersion') == desired['apiVersion'])]
        if (probe['spec'] != expected or probe.get('status') != current.get('status')
                or stable_metadata(probe) != stable_metadata(current)
                or len(owners) != 1 or owners[0]['manager'] != OWNER or owners[0]['operation'] != 'Apply'
                or foreign(probe) != foreign(current)
                or any(not contains(owners[0]['fieldsV1'], row['fieldsV1']) for row in previous_apply)):
            raise RuntimeError('Recovery dry-run changed unrelated fields or failed to restore complete Apply ownership')
        kube(*arguments, '--force-conflicts', document=desired)
        wait(lambda: converged(payload), 'recovered service catalog convergence', timeout=600)
        return {'changed': True}


if __name__ == '__main__':
    try:
        value = json.load(sys.stdin)
        print(json.dumps(recover(value['configuration'], value['recovery'])))
    except Exception:
        raise SystemExit('Recorded service source recovery failed; existing workloads and data retained') from None
