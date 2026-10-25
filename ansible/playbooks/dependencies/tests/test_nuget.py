"""Native lock changes permit graph refresh, never new execution inputs or targets."""
import base64
import copy
import json
import unittest

from playbooks.dependencies.files import nuget
from playbooks.dependencies.files.inventory import ROOT


class NugetTests(unittest.TestCase):
    def setUp(self):
        self.base = ROOT / 'platform/delivery/ci/runner/nuget'
        self.original = (self.base / 'Test/packages.lock.json').read_bytes()
        self.value = json.loads(self.original)

    def check(self, value):
        nuget.validate_lock(self.original, json.dumps(value).encode())

    def test_all_eight_existing_native_locks_are_accepted(self):
        files = sorted(self.base.glob('*/packages.lock.json'))
        self.assertEqual(len(files), 8)
        for path in files:
            with self.subTest(project=path.parent.name):
                raw = path.read_bytes()
                nuget.validate_lock(raw, raw)

    def test_graph_refresh_permits_new_locked_packages_and_project_edges(self):
        value = copy.deepcopy(self.value)
        for graph in value['dependencies'].values():
            origin = next(entry for entry in graph.values() if entry['type'] != 'Project')
            graph['Synthetic.Dependency'] = {'type': 'Transitive', 'resolved': '1.2.3-rc.1',
                'contentHash': base64.b64encode(bytes(64)).decode()}
            origin.setdefault('dependencies', {})['Synthetic.Dependency'] = '[1.2.3-rc.1, )'
            graph['Runner.PluginHost'] = {'type': 'Project', 'dependencies': {'Synthetic.Dependency': '[1.2,2.0)'}}
        self.check(value)
        for graph in value['dependencies'].values():
            del graph['Synthetic.Dependency']
            del graph['Runner.PluginHost']
            for entry in graph.values():
                entry.get('dependencies', {}).pop('Synthetic.Dependency', None)
        self.check(value)

    def test_schema_framework_and_package_fields_cannot_expand(self):
        for change in ('schema', 'framework', 'target-removal', 'source', 'type', 'project'):
            with self.subTest(change=change):
                value = copy.deepcopy(self.value)
                graph = value['dependencies']['net8.0']
                entry = next(iter(graph.values()))
                if change == 'schema':
                    value['version'] = True
                elif change == 'framework':
                    value['dependencies']['net9.0'] = {}
                elif change == 'target-removal':
                    value['dependencies'].pop('net8.0/linux-x64')
                elif change == 'source':
                    entry['source'] = 'https://unreviewed.invalid/feed'
                elif change == 'type':
                    entry['type'] = 'Command'
                else:
                    graph['Unreviewed.Project'] = {'type': 'Project'}
                with self.assertRaises(ValueError):
                    self.check(value)

    def test_identifiers_versions_and_hashes_reject_command_or_url_inputs(self):
        for name in ('../escape', 'path/package', 'package;command', 'a..b', 'a' * 101):
            with self.subTest(identifier=name):
                value = copy.deepcopy(self.value)
                value['dependencies']['net8.0'][name] = {'type': 'Project'}
                with self.assertRaises(ValueError):
                    self.check(value)
        for requested in ('https://unreviewed.invalid', '1.0; command', '(1.0)', '[,2)', '[1,]', '*', '1.0\n'):
            with self.subTest(requested=requested):
                with self.assertRaises(ValueError):
                    nuget.constraint(requested)
        valid = base64.b64encode(bytes(64)).decode()
        for digest in ('sha512-' + valid, valid[:-3] + 'B==', valid + '\n', 'a' * 64):
            with self.assertRaises(ValueError):
                nuget.content_hash(digest)

    def test_native_version_range_forms_are_allowed_without_resolving_graph(self):
        for value in ('1', '1.0', '1.0.0', '1.0.0.1', '1.0.0-rc2-24027', '[1.0]',
                      '[1.0, )', '(1.0,)', '(,1.0]', '(,1.0)', '[1,3)', '(1.0,2.0)', '[1.0.0-alpha.1, )'):
            with self.subTest(constraint=value):
                nuget.constraint(value)

    def test_duplicate_fields_and_case_ambiguous_package_names_fail(self):
        with self.assertRaises(ValueError):
            nuget.document(b'{"version":1,"version":1,"dependencies":{"net8.0":{}}}')
        value = copy.deepcopy(self.value)
        graph = value['dependencies']['net8.0']
        name = next(iter(graph))
        graph[name.lower()] = copy.deepcopy(graph[name])
        with self.assertRaises(ValueError):
            self.check(value)
