"""Shared GitHub transport and retained repository/content-owner validation."""
import json
from pathlib import Path
import re
import time
import urllib.error
import urllib.request

import yaml

ROOT = next((parent for parent in Path(__file__).resolve().parents if (parent / 'platform').is_dir()), Path('/opt/cloudlab'))
MARKER = 'Managed by CloudLab repository setup: '


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHubHTTPError(RuntimeError):
    def __init__(self, status):
        self.status = status
        super().__init__('GitHub repository operation failed: HTTP ' + str(status))


class GitHub:
    def __init__(self, token, *, deadline=None, max_response=None):
        if not token or '\n' in token or '\r' in token:
            raise RuntimeError('Repository setup requires a GitHub provisioning credential')
        self.token = token
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
        self.deadline = deadline
        self.max_response = max_response

    def request(self, method, path, body=None, missing=False):
        request = urllib.request.Request('https://api.github.com/' + path,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Bearer ' + self.token, 'Accept': 'application/vnd.github+json',
                     'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'}, method=method)
        try:
            remaining = 60 if self.deadline is None else min(15, self.deadline - time.monotonic())
            if remaining <= 0:
                raise RuntimeError('GitHub source exceeded its deadline')
            with self.opener.open(request, timeout=remaining) as response:
                if response.status == 204:
                    return None
                if self.max_response is None:
                    return json.load(response)
                raw = bytearray()
                while True:
                    if self.deadline is not None and time.monotonic() >= self.deadline:
                        raise RuntimeError('GitHub source exceeded its deadline')
                    chunk = response.read1(min(65536, self.max_response + 1 - len(raw)))
                    if not chunk:
                        break
                    raw.extend(chunk)
                    if len(raw) > self.max_response:
                        raise RuntimeError('GitHub source response exceeds its bound')
                result = json.loads(raw)
                if not isinstance(result, dict):
                    raise RuntimeError('GitHub source response must be an object')
                return result
        except urllib.error.HTTPError as error:
            if missing and error.code == 404:
                return None
            raise GitHubHTTPError(error.code) from None
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
    ):
        if not values.get(key):
            raise RuntimeError('Repository setup requires all designated repository inputs in .env')
        targets.append((role, repository(values[key]), private))
    if len({repo.lower() for _, repo, _ in targets}) != len(targets):
        raise RuntimeError('Platform and configuration repositories must be distinct')
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
