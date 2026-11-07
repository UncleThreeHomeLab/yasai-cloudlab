import base64
import unittest
from unittest.mock import patch
import yaml

from playbooks.argocd.files.private_sources import argo_values


ISSUER = 'https://login.example.test/realms/platform'
ORIGIN = 'https://argo-public.example.test'
PRIVATE = 'https://argo-private.example.test'
REVISION = 'a' * 40
VALUES = {'PRIVATE_CONFIG_REPOSITORY': 'https://github.com/example/private-config.git'}


class StubApi:
    def __init__(self, blob, repo='default'):
        self.blob = blob
        self.repo = repo if repo != 'default' else {
            'full_name': 'example/private-config', 'private': True, 'fork': False,
            'archived': False, 'description': 'Managed by CloudLab repository setup: private-config'}

    def request(self, method, path, missing=False):
        if path == 'repos/example/private-config':
            return dict(self.repo) if self.repo else None
        assert path == 'repos/example/private-config/contents/identity/argo-values.yaml?ref=' + REVISION
        return {'type': 'file', 'encoding': 'base64', 'size': len(self.blob),
                'content': base64.b64encode(self.blob).decode()}


def overlay(issuer=ISSUER, origin=ORIGIN, private=PRIVATE, mutate=None):
    config = {'name': 'Keycloak', 'issuer': issuer, 'clientID': 'argocd',
              'enablePKCEAuthentication': True, 'refreshTokenThreshold': '2m',
              'requestedScopes': ['openid', 'profile', 'email']}
    document = {'argo-cd': {'configs': {
        'cm': {'url': origin, 'additionalUrls': yaml.safe_dump([private], sort_keys=True),
               'users.session.duration': '10m',
               'oidc.config': yaml.safe_dump(config, sort_keys=True)},
        'rbac': {'policy.default': 'role:no-access', 'scopes': '[groups]',
                 'policy.csv': '\n'.join([
                     'g, /platform-admin, role:admin',
                     'g, /developer, role:developer',
                     'g, /viewer, role:viewer',
                     'p, role:developer, applications, get, cloudlab-public/*, allow',
                     'p, role:developer, applications, sync, cloudlab-public/*, allow',
                     'p, role:developer, logs, get, cloudlab-public/*, allow',
                     'p, role:viewer, applications, get, cloudlab-public/*, allow',
                     'p, role:viewer, logs, get, cloudlab-public/*, allow'])}}}}
    if mutate:
        mutate(document)
    return yaml.safe_dump(document, sort_keys=True).encode()


class ArgoValuesTests(unittest.TestCase):
    def accept(self, blob, revision=REVISION, issuer=ISSUER, origin=ORIGIN,
               additional=None, repo='default'):
        api = StubApi(blob) if repo == 'default' else StubApi(blob, repo)
        return argo_values(api, VALUES, revision, issuer, origin,
                           [PRIVATE] if additional is None else additional)

    def test_matching_overlay_returns_helm_contract(self):
        result = self.accept(overlay())
        self.assertEqual(set(result), {'helm'})
        self.assertEqual(result['helm']['argo-cd']['configs']['cm']['url'], ORIGIN)

    def test_tampered_overlay_is_refused(self):
        cases = [lambda doc: doc['argo-cd']['configs']['cm'].__setitem__('url', 'https://evil.example.test'),
                 lambda doc: doc['argo-cd']['configs'].__setitem__('extra', True),
                 lambda doc: doc['argo-cd']['configs']['rbac'].__setitem__('policy.default', 'role:readonly')]
        for mutate in cases:
            with self.subTest():
                with self.assertRaises(RuntimeError):
                    self.accept(overlay(mutate=mutate))

    def test_overlay_for_other_issuer_or_origin_is_refused(self):
        with self.assertRaises(RuntimeError):
            self.accept(overlay(issuer='https://login.example.test/realms/other'))
        with self.assertRaises(RuntimeError):
            self.accept(overlay(origin='https://argo-public.example.test.evil.test'))

    def test_non_immutable_revision_is_refused(self):
        for revision in ('main', 'a' * 39, '', None):
            with self.subTest(revision=revision):
                with self.assertRaises(ValueError):
                    self.accept(overlay(), revision=revision)

    def test_missing_designated_repository_is_refused(self):
        with self.assertRaises(RuntimeError):
            self.accept(overlay(), repo=None)

    def test_non_platform_issuer_is_refused(self):
        with self.assertRaises(ValueError):
            self.accept(overlay(), issuer='https://login.example.test/realms/other')
        with self.assertRaises(ValueError):
            self.accept(overlay(), issuer='http://login.example.test/realms/platform')

    def test_origins_must_be_distinct_bounded_pair(self):
        with self.assertRaises(ValueError):
            self.accept(overlay(), additional=[ORIGIN])
        with self.assertRaises(ValueError):
            self.accept(overlay(), additional=[])
        with self.assertRaises(ValueError):
            self.accept(overlay(), origin='https://argo-public.example.test/console')
        with self.assertRaises(ValueError):
            self.accept(overlay(), additional=['https://argo-private.example.test/console'])

    def test_oversized_or_misreported_source_is_refused(self):
        blob = overlay()
        api = StubApi(blob)
        with patch.object(StubApi, 'request', lambda self, method, path, missing=False: (
                {'full_name': 'example/private-config', 'private': True, 'fork': False,
                 'archived': False,
                 'description': 'Managed by CloudLab repository setup: private-config'}
                if path == 'repos/example/private-config' else
                {'type': 'file', 'encoding': 'base64', 'size': 1048577,
                 'content': base64.b64encode(blob).decode()})):
            with self.assertRaises(RuntimeError):
                argo_values(api, VALUES, REVISION, ISSUER, ORIGIN, [PRIVATE])
        with patch.object(StubApi, 'request', lambda self, method, path, missing=False: (
                {'full_name': 'example/private-config', 'private': True, 'fork': False,
                 'archived': False,
                 'description': 'Managed by CloudLab repository setup: private-config'}
                if path == 'repos/example/private-config' else
                {'type': 'file', 'encoding': 'base64', 'size': len(blob) + 1,
                 'content': base64.b64encode(blob).decode()})):
            with self.assertRaises(RuntimeError):
                argo_values(api, VALUES, REVISION, ISSUER, ORIGIN, [PRIVATE])


if __name__ == '__main__':
    unittest.main()
