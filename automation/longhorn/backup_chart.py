"""Render backup declarations with private destination inputs kept on stdin."""
import json
from pathlib import Path
import re
import subprocess
import sys

import yaml

from backup_policy import load_policy

REPOSITORY = Path(__file__).resolve().parents[2]
ROOT = REPOSITORY / 'platform/storage/longhorn-backup'
OWNER = 'ansible-longhorn-backup'


def render(inputs, secret_only=False):
    store = inputs['store']
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', store):
        raise ValueError('Invalid store reference')
    values = {'bootstrapSecretOnly': secret_only, 'store': store}
    if not secret_only:
        if (not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9.-]{1,62}', inputs['bucket'])
                or not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,62}', inputs['region'])):
            raise ValueError('Invalid private backup destination')
        values['destination'] = {'bucket': inputs['bucket'], 'region': inputs['region']}
    command = ['helm', 'template', 'cloudlab-longhorn-backup', str(ROOT),
               '--namespace', 'longhorn-system', '--values', '-']
    def template():
        return subprocess.run(command, input=json.dumps(values), text=True,
                              capture_output=True, timeout=60, check=True).stdout
    first = template()
    if first != template():
        raise ValueError('Backup chart is nondeterministic')
    objects = [obj for obj in yaml.safe_load_all(first) if obj]
    if (sorted(x['kind'] for x in objects) != sorted(['ExternalSecret'] if secret_only else ['ExternalSecret', 'BackupTarget', 'RecurringJob'])):
        raise ValueError('Backup chart declaration inventory changed')
    if any(obj['metadata'].get('namespace') != 'longhorn-system' for obj in objects):
        raise ValueError('Backup chart escaped its namespace')
    return objects, values


def payload(inputs, secret_only=False):
    objects, values = render(inputs, secret_only)
    policy = load_policy()
    source = yaml.safe_load((REPOSITORY / 'gitops/roots/public/values.yaml').read_text())
    settings = source['longhornBackup']
    app = {'apiVersion': 'argoproj.io/v1alpha1', 'kind': 'Application',
        'metadata': {'name': 'cloudlab-longhorn-backup', 'namespace': source['namespace'],
                     'labels': {'cloudlab.io/owner': OWNER}},
        'spec': {'project': 'cloudlab-longhorn-backup',
            'source': {'repoURL': source['repository'], 'targetRevision': source['revision'],
                       'path': 'platform/storage/longhorn-backup',
                       'helm': {'releaseName': 'cloudlab-longhorn-backup', 'valuesObject': values}},
            'destination': {'server': 'https://kubernetes.default.svc', 'namespace': 'longhorn-system'},
            'syncPolicy': {'automated': {'enabled': settings['reconcile'], 'prune': False,
                                       'selfHeal': True, 'allowEmpty': False},
                'syncOptions': ['FailOnSharedResource=true', 'DisableClientSideApplyMigration=true'],
                'retry': {'limit': 5, 'backoff': {'duration': '5s', 'factor': 2, 'maxDuration': '1m'}}}}}
    inventory = [{'apiVersion': version, 'kind': kind, 'metadata': {'name': name, 'namespace': 'longhorn-system'}}
                 for version, kind, name in [('external-secrets.io/v1', 'ExternalSecret', policy['external_secret_name']),
                    ('longhorn.io/v1beta2', 'BackupTarget', 'default'),
                    ('longhorn.io/v1beta2', 'RecurringJob', policy['job_name'])]]
    revision = subprocess.check_output(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'], text=True).strip()
    return {'items': objects, 'inventory': inventory, 'secret': policy['secret_name'], 'app': app,
            'revision': revision, 'enabled': settings['enabled'], 'owner': OWNER}


if __name__ == '__main__':
    try:
        print(json.dumps(payload(json.load(sys.stdin), sys.argv[1:] == ['secret'])))
    except Exception:
        raise SystemExit('Backup chart validation failed; private destination and diagnostics withheld') from None
