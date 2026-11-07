"""Admission verify references resolve or carry an explicit stat gate.

Every lookup('file', ...) target, `python -m` module and script: entry in
admission/verify.yml must resolve inside the checkout, or its task must be
gated on a stat probe over the same retired tree. Catches silent
retirement breaks without a cluster. The Jinja gate check is a tripwire,
not a template evaluation: a missing lookup must sit inside a
{% if ...stat.exists... %} span over a stat-probed parent.
"""
import json
import re
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[4]
PLAYBOOK = ROOT / 'ansible/playbooks/admission/verify.yml'


def tasks():
    plays = yaml.safe_load(PLAYBOOK.read_text())
    found = []
    for play in plays:
        for task in play.get('tasks', []):
            if any(key in task for key in ('import_tasks', 'include_tasks', 'import_playbook')):
                raise AssertionError('Uncovered task import in admission verify: ' + str(task))
            found.append(task)
    return found


def stat_probes(all_tasks):
    probes = set()
    for task in all_tasks:
        stat = task.get('ansible.builtin.stat', {})
        if isinstance(stat, dict) and isinstance(stat.get('path'), str):
            probes.add(stat['path'].replace('/workspace/', '', 1))
    return probes


def gated_spans(text):
    return [(match.start(), match.end(), 'stat.exists' in match.group(1))
            for match in re.finditer(r'{% if (.*?) %}(.*?){% endif %}', text, re.S)]


def gated_lookup(offset, spans, probes, target):
    return any(start <= offset <= end and gated and
               any(target == probe or target.startswith(probe.rstrip('/') + '/') for probe in probes)
               for start, end, gated in spans)


class VerifyRefsTests(unittest.TestCase):
    def test_verify_references_resolve_or_gate_on_a_stat_probe(self):
        text = PLAYBOOK.read_text()
        all_tasks = tasks()
        probes = stat_probes(all_tasks)
        spans = gated_spans(text)
        for task in all_tasks:
            body = json.dumps(task)
            for target in re.findall(r"lookup\('file',\s*'([^']+)'\)", body):
                relative = target.replace('/workspace/', '', 1)
                offset = text.find(target)
                with self.subTest(ref=target):
                    self.assertTrue(
                        (ROOT / relative).exists() or
                        (offset >= 0 and gated_lookup(offset, spans, probes, relative)),
                        'Unresolved and ungated lookup: ' + target)
            for module in re.findall(r'python(?:3)?\s+-m\s+([\w.]+)', body):
                relative = module.replace('.', '/') + '.py'
                candidates = [ROOT / relative, ROOT / 'ansible' / relative]
                when = json.dumps(task.get('when', ''))
                with self.subTest(ref=module):
                    self.assertTrue(
                        any(path.exists() for path in candidates) or
                        ('stat.exists' in when and any(
                            relative == probe or relative.startswith(probe.rstrip('/') + '/') or
                            ('ansible/' + relative) == probe or
                            ('ansible/' + relative).startswith(probe.rstrip('/') + '/')
                            for probe in probes)),
                        'Unresolved and ungated module: ' + module)
            script = task.get('ansible.builtin.script', {})
            command = script.get('cmd', '') if isinstance(script, dict) else ''
            if command:
                entry = command.split()[0]
                with self.subTest(ref=entry):
                    self.assertTrue((PLAYBOOK.parent / entry).exists(),
                                    'Unresolved script entry: ' + entry)


if __name__ == '__main__':
    unittest.main()
