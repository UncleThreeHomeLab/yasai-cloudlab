"""Read the chart-owned policy locally or its explicitly installed host copy."""
import json
from pathlib import Path


def load_policy():
    source = Path(__file__).resolve().parents[2] / 'platform/storage/longhorn-backup/policy.json'
    if not source.is_file():
        source = Path(__file__).with_name('backup-policy.json')
    return json.loads(source.read_text())
