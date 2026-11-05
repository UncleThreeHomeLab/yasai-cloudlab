"""Attested removal of the replaced data writer and its raw desired-value cache."""
import hashlib
import importlib.util
import json
import marshal
from pathlib import Path
import re
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
from playbooks.data.files import control, handoff, native

WRITER = Path('/opt/cloudlab/playbooks/data/files/configuration.py')
WRITER_SHA256 = 'd5791e9d458390ae92a5bfe29ae440b96b59743ee11a7395aa9674e5462687d4'


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise RuntimeError('Retired data cache has duplicate JSON keys')
        result[key] = value
    return result


def retire():
    with control.locked():
        owner = handoff.state()
        value = handoff.journal(owner)
        if not value or value['phase'] != 'completed' or not owner.get('settings_uid'):
            raise RuntimeError('Data runtime retirement requires the completed native handoff')
        source = native.operation()
        source.settings()
        cache = control.BASE / 'desired.json'
        present = native.authority_path(WRITER, missing=True) is not None
        raw = WRITER.read_bytes() if present else None
        if raw is not None and hashlib.sha256(raw).hexdigest() != WRITER_SHA256:
            raise RuntimeError('Retired data writer checksum differs from its approved source')
        bytecode = []
        native.authority_path(WRITER.parent / '__pycache__' / '.retirement-probe', missing=True)
        for path in [WRITER.with_suffix('.pyc'), *WRITER.parent.joinpath('__pycache__').glob('configuration.*.pyc')]:
            if native.authority_path(path, missing=True) is None:
                continue
            match = re.fullmatch(r'configuration[.]cpython-[0-9]+(?:[.]opt-([12]))?[.]pyc', path.name)
            if raw is None or (path != WRITER.with_suffix('.pyc') and not match):
                raise RuntimeError('Retired data bytecode has no approved source provenance')
            data = path.read_bytes()
            if len(data) > 1024 * 1024 or data[:4] != importlib.util.MAGIC_NUMBER:
                raise RuntimeError('Retired data bytecode has an unsupported format')
            expected = compile(raw, str(WRITER), 'exec', dont_inherit=True, optimize=int(match[1] or 0) if match else 0)
            if marshal.loads(data[16:]) != expected:
                raise RuntimeError('Retired data bytecode differs from the approved writer')
            bytecode.append(path)
        cached = native.authority_path(cache, missing=True) is not None
        if cached:
            actual = json.loads(cache.read_text(), object_pairs_hook=unique)
            expected = value['specs'][native.APP]['source']['helm']['valuesObject']
            canonical = lambda row: json.dumps(row, sort_keys=True, allow_nan=False)
            if canonical(actual) != canonical(expected):
                raise RuntimeError('Retired data cache differs from the captured raw legacy values')
        for path in [*bytecode, *([WRITER] if present else []), *([cache] if cached else [])]:
            path.unlink()
        return bool(bytecode or present or cached)


if __name__ == '__main__':
    try:
        print(json.dumps({'changed': retire()}))
    except Exception:
        raise SystemExit('Data runtime retirement blocked; provenance retained') from None
