"""Read immutable public baseline bytes supplied by the trusted export owner."""
import base64
import json
from pathlib import Path

from .security import owned_path


def baseline(root, relative):
    plan = Path('/plan.json')
    if plan.is_file():
        value = json.loads(plan.read_bytes())
        if relative not in value['baseFiles']:
            raise ValueError('Maintenance input is outside the exported owner scope')
        return base64.b64decode(value['baseFiles'][relative], validate=True)
    return owned_path(root, relative).read_bytes()
