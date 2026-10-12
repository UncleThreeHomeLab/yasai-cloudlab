"""Synthetic inputs; no VM, vault or service credentials."""
from pathlib import Path
import yaml


def definition():
    return yaml.safe_load((Path(__file__).resolve().parents[3] / 'charts/service/values.yaml').read_text())


def approval():
    return {'name': 'synthetic', 'namespace': 'cloudlab-app-synthetic',
            'repository': 'https://github.com/example/fixture.git', 'revision': 'a' * 40,
            'valuesPath': 'apps/synthetic.yaml', 'secretReferences': [], 'configMaps': []}
