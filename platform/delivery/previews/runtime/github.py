"""Read bounded exact GitHub objects; absence/errors never mean PR closure."""
import base64
import json
import re
import time
import urllib.error
import urllib.request

try:
    from .contract import SOURCE_PATH, source, approval, verify_blob, validate_pull, discovery_lease, LEASE_MARGIN
except ImportError:
    from contract import SOURCE_PATH, source, approval, verify_blob, validate_pull, discovery_lease, LEASE_MARGIN


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class GitHub:
    def __init__(self, token='', *, private=False, lease=None):
        self.private, self.lease = private, None
        if private:
            try:
                self.lease = discovery_lease(dict(lease, token=token))
            except (ValueError, TypeError):
                token = ''
        if not isinstance(token, str) or '\n' in token or '\r' in token:
            raise ValueError('Invalid preview discovery credential')
        self.token = token

    def allows(self, row, now):
        return not self.private or bool(self.lease and self.lease['repository'] == row['repository'] and
            self.lease['repositoryId'] == row['repositoryId'] and self.lease['expiresAt'] > now and
            row['expiresAt'] + LEASE_MARGIN <= self.lease['expiresAt'])

    def request(self, path):
        if self.private and (not self.lease or self.lease['expiresAt'] <= int(time.time())):
            raise RuntimeError('Private preview discovery lease is unavailable')
        headers = {'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
        if self.token:
            headers['Authorization'] = 'Bearer ' + self.token
        request = urllib.request.Request('https://api.github.com/' + path, headers=headers)
        try:
            with urllib.request.build_opener(NoRedirect()).open(request, timeout=10) as response:
                raw = response.read(262145)
                if len(raw) > 262144 or response.headers.get('Link'):
                    raise ValueError('Incomplete or oversized preview API response')
                return json.loads(raw)
        except Exception:
            raise RuntimeError('Preview discovery unavailable; diagnostics withheld') from None

    def pull(self, row):
        result = self.request('repos/' + row['repository'] + '/pulls/' + str(row['pullRequest']))
        if result.get('base', {}).get('repo', {}).get('private') is not self.private:
            raise ValueError('Preview repository visibility differs from its approved discovery mode')
        return result

    def blob(self, row):
        prefix = 'repos/' + row['repository'] + '/git/'
        commit = self.request(prefix + 'commits/' + row['sourceSha'])
        root = commit.get('tree', {}).get('sha')
        if commit.get('sha') != row['sourceSha'] or not isinstance(root, str) or not re.fullmatch('[a-f0-9]{40}', root):
            raise ValueError('Preview source commit identity differs')
        def entry(tree_sha, name, mode, kind):
            tree = self.request(prefix + 'trees/' + tree_sha)
            if (tree.get('sha') != tree_sha or tree.get('truncated') is not False or
                    not isinstance(tree.get('tree'), list) or len(tree['tree']) > 1000):
                raise ValueError('Preview source tree metadata is incomplete')
            matches = [item for item in tree['tree'] if item.get('path') == name]
            if (len(matches) != 1 or matches[0].get('mode') != mode or matches[0].get('type') != kind or
                    not isinstance(matches[0].get('sha'), str) or not re.fullmatch('[a-f0-9]{40}', matches[0]['sha'])):
                raise ValueError('Preview source requires a regular non-executable file in its exact tree')
            return matches[0]
        directory, filename = SOURCE_PATH.split('/')
        subtree = entry(root, directory, '040000', 'tree')
        blob = entry(subtree['sha'], filename, '100644', 'blob')
        obj = self.request('repos/' + row['repository'] + '/contents/' + SOURCE_PATH + '?ref=' + row['sourceSha'])
        if (not isinstance(obj, dict) or obj.get('type') != 'file' or obj.get('path') != SOURCE_PATH or
                obj.get('encoding') != 'base64' or type(obj.get('size')) is not int or not 1 <= obj['size'] <= 16384 or
                obj.get('sha') != blob['sha'] or obj['size'] != blob.get('size') or
                obj.get('submodule_git_url') or obj.get('target')):
            raise ValueError('Preview source must be one bounded regular JSON file')
        raw = base64.b64decode(''.join(obj['content'].split()), validate=True)
        if len(raw) != obj['size']:
            raise ValueError('Preview source size differs from its API metadata')
        source(raw)
        return raw

    def verified(self, row):
        approval(row)
        if not self.allows(row, int(time.time())):
            raise RuntimeError('Preview approval exceeds its repository discovery lease')
        pull = self.pull(row)
        validate_pull(row, pull)
        verify_blob(row, self.blob(row))
        return pull
