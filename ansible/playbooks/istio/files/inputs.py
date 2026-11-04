"""Authenticated shared gateway inputs; no provider or live configuration snapshots."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

import yaml


def prepare(values, public, binding, active_revision, *, expected_revision=None):
    from playbooks.argocd.files.github_app import configuration_revision
    from playbooks.argocd.files.github_setup import repository
    from playbooks.keycloak.files.private_source import argo_values, decode_contents
    private = values.get('PRIVATE_CONFIG_REPOSITORY')
    pin = public.get('mesh', {}).get('configuration', {}).get('revision')
    if (not isinstance(binding, dict) or set(binding) != {'valuesRepository', 'valuesRevision'}
            or binding['valuesRepository'] != private
            or any(not isinstance(v, str) or not re.fullmatch('[a-f0-9]{40}', v)
                   for v in (binding['valuesRevision'], pin, active_revision))):
        raise ValueError('Native gateway source bindings are invalid')
    repo = repository(private)
    root = Path(__file__).resolve().parents[4]

    def render(path, content, *, defaults=False):
        chart = root / path
        result = subprocess.run(['helm', 'template', 'cloudlab-gateways', str(chart),
            *(['-f', str(chart / 'values.json')] if defaults else []), '-f', '-'],
            input=json.dumps(content), capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise ValueError('Native gateway declarations cannot be rendered')
        return [obj for obj in yaml.safe_load_all(result.stdout) if obj]

    def read(client, revision):
        if expected_revision is not None and revision != expected_revision:
            raise ValueError('Private gateway revision changed after approval')

        def document(path, sha):
            obj = client.request('GET', 'repos/' + repo + '/contents/' + path + '?ref=' + sha)
            if (not isinstance(obj, dict) or obj.get('type') != 'file' or obj.get('encoding') != 'base64'
                    or type(obj.get('size')) is not int or not 0 <= obj['size'] <= 65536):
                raise ValueError('Gateway inputs require bounded regular files')
            raw = decode_contents(obj)
            if len(raw) != obj['size'] or len(raw) > 65536:
                raise ValueError('Gateway input size differs from its bounded file contract')
            return yaml.safe_load(raw)

        selected = document('platform/certificates.yaml', revision)
        if (not isinstance(selected, dict) or set(selected) != {'zone', 'production'}
                or selected['production'] is not True or not isinstance(selected['zone'], str)):
            raise ValueError('Gateway certificate inputs violate their shared schema')

        def identity(sha):
            overlay = document('identity/argo-values.yaml', sha)
            # Validate native schema and exact origins before using them to check the producer.
            render('platform/connectivity/gateways', dict(selected, **overlay, sharedInputs=True), defaults=True)
            cm = overlay['argo-cd']['configs']['cm']
            return argo_values(client, values, sha, 'https://login.' + selected['zone'] + '/realms/platform',
                               cm['url'], yaml.safe_load(cm['additionalUrls']))['helm']

        # Current authorization/revocations must pass before historical approved values are read.
        current = identity(revision)
        approved = current if binding['valuesRevision'] == revision else identity(binding['valuesRevision'])
        resources = render('platform/connectivity/gateways', dict(selected, **approved, sharedInputs=True), defaults=True)
        configuration = dict(public, identity=dict(public['identity'], argo=binding))
        objects = render('gitops/roots/public', configuration)
        def owned(kind, name):
            return next(obj for obj in objects if obj['kind'] == kind and obj['metadata']['name'] == name)
        return {'repository': public['repository'], 'public_revision': active_revision,
            'configuration_revision': pin, 'private_repository': private, 'private_revision': revision,
            'identity_revision': binding['valuesRevision'], 'values': selected, 'resources': resources,
            'application': owned('Application', 'cloudlab-gateways'),
            'project': owned('AppProject', 'cloudlab-gateways'),
            'reader': owned('ExternalSecret', 'cloudlab-gateways-source')}
    try:
        return configuration_revision(values, read=read)
    except Exception:
        raise ValueError('Authenticated gateway inputs are unavailable or invalid') from None


if __name__ == '__main__':
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
        from dotenv import dotenv_values
        envelope = json.load(sys.stdin)
        identity = envelope['root'].get('spec', {}).get('source', {}).get('helm', {}).get('valuesObject', {}).get('identity', {})
        native = None
        if 'argo' in identity:
            root = Path(__file__).resolve().parents[4]
            values = dotenv_values(root / '.env', interpolate=False)
            os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
            native = prepare(values, yaml.safe_load((root / 'gitops/roots/public/values.yaml').read_text()),
                             identity['argo'], envelope['public']['revision'])
        print(json.dumps({'native': native}))
    except Exception:
        raise SystemExit('Native gateway inputs unavailable; private diagnostics withheld') from None
