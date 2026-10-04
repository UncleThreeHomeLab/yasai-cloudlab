"""Independent read-only 1Password retrieval, with sanitized failures."""
import json
import subprocess


def fields(item, required):
    result = subprocess.run(['op', 'item', 'get', item, '--vault', 'CloudLab', '--format', 'json'],
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError('Cannot read required CloudLab item: ' + item)
    document = json.loads(result.stdout)
    values = {}
    for label in required:
        matches = [f.get('value') for f in document.get('fields', []) if f.get('label') == label]
        if len(matches) != 1 or not matches[0]:
            raise RuntimeError('Missing or ambiguous field in ' + item + ': ' + label)
        values[label] = matches[0]
    return values
