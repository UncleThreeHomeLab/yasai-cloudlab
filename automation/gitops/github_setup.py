"""Explicit repository provisioning; never changes existing visibility or contents."""
import json
from pathlib import Path
import re
import sys
import urllib.error
import urllib.request

from dotenv import dotenv_values
import yaml

ROOT = Path(__file__).resolve().parents[2]
MARKER = 'Managed by CloudLab repository setup: '


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token):
        if not token or '\n' in token or '\r' in token:
            raise RuntimeError('Repository setup requires a GitHub provisioning credential')
        self.token = token
        self.opener = urllib.request.build_opener(NoRedirect())

    def request(self, method, path, body=None, missing=False):
        request = urllib.request.Request('https://api.github.com/' + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                     'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'}, method=method)
        try:
            with self.opener.open(request, timeout=60) as response:
                return json.load(response)
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            raise RuntimeError('GitHub repository operation failed: HTTP ' + str(error.code)) from None
        except (urllib.error.URLError, ValueError):
            raise RuntimeError('GitHub repository operation unavailable') from None


def repository(url):
    match = re.fullmatch(r'https://github[.]com/([A-Za-z0-9][A-Za-z0-9-]*)/([A-Za-z0-9][A-Za-z0-9_.-]*)[.]git', url or '')
    if not match:
        raise RuntimeError('Repository inputs must be explicit GitHub HTTPS .git URLs')
    return match.group(1) + '/' + match.group(2)


def configuration(values):
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
    targets = [('public-platform', repository(public), False)]
    for key, role, private in (
        ('PRIVATE_CONFIG_REPOSITORY', 'private-config', True),
        ('PUBLIC_TEST_REPOSITORY', 'public-fixture', False),
        ('PRIVATE_TEST_REPOSITORY', 'private-fixture', True),
    ):
        if not values.get(key):
            raise RuntimeError('Repository setup requires all designated repository inputs in .env')
        targets.append((role, repository(values[key]), private))
    if len({repo.lower() for _, repo, _ in targets}) != len(targets):
        raise RuntimeError('Platform, configuration and fixture repositories must be distinct')
    if len({repo.split('/')[0].lower() for _, repo, _ in targets}) != 1:
        raise RuntimeError('Repository setup is restricted to the platform organization')
    return targets


def inspect(api, role, repo, private):
    current = api.request('GET', 'repos/' + repo, missing=True)
    if current is not None:
        if (current.get('full_name', '').lower() != repo.lower() or
                current.get('private') != private or current.get('fork') or current.get('archived') or
                current.get('description') != MARKER + role):
            raise RuntimeError('Existing repository differs from the declared setup; adoption refused')
    return current


def provision(api, targets):
    # Validate every existing target before creating any missing one.
    existing = [inspect(api, *target) for target in targets]
    changed = 0
    for (role, repo, private), current in zip(targets, existing):
        if current is None:
            owner, name = repo.split('/')
            api.request('POST', 'orgs/' + owner + '/repos', {
                'name': name, 'private': private, 'description': MARKER + role,
                'auto_init': False, 'has_issues': False, 'has_projects': False,
                'has_wiki': False, 'has_discussions': False})
            if inspect(api, role, repo, private) is None:
                raise RuntimeError('Created repository could not be verified')
            changed += 1
    return {'repositories_verified': len(targets), 'repositories_created': changed}


def inputs():
    values = dotenv_values(ROOT / '.env', interpolate=False)
    # Optional stdin injection lets an existing local gh login avoid storing a
    # second token. Neither token form is required by normal cluster bootstrap.
    token = values.get('GITHUB_PROVISION_TOKEN')
    if not token and not sys.stdin.isatty():
        token = sys.stdin.readline().strip()
    return values, GitHub(token)


if __name__ == '__main__':
    try:
        values, api = inputs()
        print(json.dumps(provision(api, configuration(values))))
    except Exception as error:
        raise SystemExit(str(error) if isinstance(error, RuntimeError) else 'Repository setup failed; private diagnostics withheld') from None
