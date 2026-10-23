"""Credential-free release definitions and bounded live fixture scope."""
from pathlib import Path
import yaml

ROOT = Path(__file__).resolve().parents[4]


def definition(host='release.internal.example.invalid', artifact=None):
    value = yaml.safe_load((ROOT / 'charts/service/values.yaml').read_text())
    value.update(name='release-proof', owner='platform')
    value['rollouts']['enabled'] = True
    value['ports'].append({'name': 'http-metrics', 'port': 9091})
    value['exposure'] = {'class': 'private', 'hostname': host, 'access': 'tailnet', 'path': '/canary-proof', 'port': 8080}
    value['health'] = {kind: {'path': '/ready', 'port': 'http'} for kind in ('readiness', 'liveness')}
    if artifact:
        value['image'] = artifact['image']
        value['imagePullSecrets'] = [{'name': 'harbor-application-pull'}]
        value['artifactPolicyHash'] = artifact['policy_hash']
    return value
