"""Resolve required private source metadata without publishing it."""
import json
from pathlib import Path
import sys

from dotenv import dotenv_values
import yaml

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from automation.gitops.render import committed_payload
from automation.gitops.github_setup import repository


def payload():
    result = committed_payload()
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())
    if not public.get('identity', {}).get('enabled'):
        raise RuntimeError('Identity operator and dedicated CNPG contract must be reviewed and enabled first')
    private = dotenv_values(ROOT / '.env', interpolate=False).get('PRIVATE_CONFIG_REPOSITORY')
    private_name = repository(private)
    public_name = repository(result['repository'])
    if private_name == public_name or private_name.split('/')[0] != public_name.split('/')[0]:
        raise RuntimeError('Identity private source must be a distinct designated configuration repository')
    return {key: result[key] for key in ('repository', 'branch', 'revision')} | {
        'private_repository': private, 'private_branch': 'main'}


if __name__ == '__main__':
    try:
        print(json.dumps(payload()))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else
                         'Required identity source metadata unavailable; no changes made') from None
