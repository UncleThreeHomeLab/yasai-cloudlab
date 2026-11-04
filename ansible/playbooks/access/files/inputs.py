"""Authenticated access observations from approved private Git and public charts."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import yaml

SLOT = '0' * 40


def observation(public, private):
    pin = public.get('access', {}).get('configuration', {}).get('revision')
    if not isinstance(pin, str) or not re.fullmatch('[a-f0-9]{40}', pin):
        raise ValueError('Access observation requires its published immutable chart pin')
    selected = copy.deepcopy(public)
    selected['access']['configuration']['enabled'] = True
    selected.setdefault('identity', {}).update(enabled=True, argo={'valuesRepository': private, 'valuesRevision': SLOT})
    root = Path(__file__).resolve().parents[4]
    result = subprocess.run(['helm', 'template', 'root', str(root / 'gitops/roots/public'), '-f', '-'],
        input=json.dumps(selected), capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise ValueError('Access observation declarations cannot be rendered')
    objects = [obj for obj in yaml.safe_load_all(result.stdout) if obj]
    return {'revision': pin, **{key: next(obj for obj in objects if obj['kind'] == kind and obj['metadata']['name'] == name)
        for key, kind, name in (('application', 'Application', 'cloudlab-access'),
                               ('project', 'AppProject', 'cloudlab-access'),
                               ('reader', 'ExternalSecret', 'cloudlab-access-source'))}}


def prepare(values, public, binding, active_revision):
    from playbooks.argocd.files.github_app import configuration_revision
    from playbooks.argocd.files.access_activation import prepare as administrator
    private = values.get('PRIVATE_CONFIG_REPOSITORY')
    if (not isinstance(binding, dict) or set(binding) != {'valuesRepository', 'valuesRevision'}
            or binding['valuesRepository'] != private or not isinstance(binding['valuesRevision'], str)
            or not re.fullmatch('[a-f0-9]{40}', binding['valuesRevision'])
            or not isinstance(active_revision, str) or not re.fullmatch('[a-f0-9]{40}', active_revision)):
        raise ValueError('Native access requires its designated approved source')
    def read(client, current_revision):
        evidence = administrator(public, private, binding['valuesRevision'], client)
        if evidence['administratorHash'] is None:
            raise ValueError('Approved native access declaration is missing')
        template = observation(public, private)
        template['application']['spec']['sources'][1]['targetRevision'] = binding['valuesRevision']
        return {'repository': public['repository'], 'public_revision': active_revision,
            'configuration_revision': template['revision'], 'private_repository': private,
            'private_revision': binding['valuesRevision'], 'evidence': evidence,
            **{k: template[k] for k in ('application', 'project', 'reader')}}
    try:
        return configuration_revision(values, read=read)
    except Exception:
        raise ValueError('Authenticated approved access inputs unavailable or invalid') from None


if __name__ == '__main__':
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
        from dotenv import dotenv_values
        envelope = json.load(sys.stdin)
        root = Path(__file__).resolve().parents[4]
        public = yaml.safe_load((root / 'gitops/roots/public/values.yaml').read_text())
        identity = envelope['root'].get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {}).get('identity', {})
        native = None
        if 'argo' in identity:
            values = dotenv_values(root / '.env', interpolate=False)
            os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
            native = prepare(values, public, identity['argo'], envelope['public']['revision'])
        print(json.dumps({'native': native}))
    except Exception:
        raise SystemExit('Approved native access inputs unavailable; private diagnostics withheld') from None
