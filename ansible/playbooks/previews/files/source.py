"""Read approved preview intent from the existing private contents-only owner."""
import json
import os
from pathlib import Path

from dotenv import dotenv_values
from playbooks.argocd.files.github_app import app_token, verify_installation
from playbooks.argocd.files.github_setup import GitHub, repository
from playbooks.keycloak.files.private_source import decode_contents
from playbooks.secrets.files.vault import fields
from playbooks.previews.files.contract import runtime_catalog

ROOT = Path(__file__).resolve().parents[4]


def read():
    values = dotenv_values(ROOT / '.env', interpolate=False)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = values.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    credentials = fields('github-argocd', ('APP_ID', 'INSTALLATION_ID', 'PRIVATE_KEY'))
    api = GitHub(app_token(credentials))
    route = 'app/installations/' + credentials['INSTALLATION_ID']
    verify_installation(api.request('GET', route), credentials['APP_ID'])
    repo = repository(values.get('PRIVATE_CONFIG_REPOSITORY'))
    token = api.request('POST', route + '/access_tokens', {
        'repositories': [repo.split('/')[1]], 'permissions': {'contents': 'read'}})['token']
    reader = GitHub(token)
    try:
        revision = reader.request('GET', 'repos/' + repo + '/git/ref/heads/main')['object']['sha']
        blob = reader.request('GET', 'repos/' + repo + '/contents/previews/catalog.json?ref=' + revision)
        value = json.loads(decode_contents(blob))
        if not isinstance(value, dict) or set(value) != {'catalog'}:
            raise ValueError('Preview private values require one complete catalog')
        return runtime_catalog(value['catalog']), revision, values
    finally:
        reader.request('DELETE', 'installation/token')
