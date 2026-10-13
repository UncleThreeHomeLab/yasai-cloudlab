"""Synthetic notes API. SQL and S3 use only application-scoped credentials."""
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import threading
import time
import urllib.request

from tokens import validated_claims
from s3 import S3
import telemetry

MAX_BODY = 65536
KEYS = {'expires': 0, 'document': {'keys': []}}
KEY_LOCK = threading.Lock()


def credential(directory, name):
    return (Path(directory) / name).read_text().strip()


def signing_keys():
    with KEY_LOCK:
        if KEYS['expires'] <= time.time():
            # Issuer is administrator-supplied. Never follow untrusted JWT URLs.
            issuer = os.environ['OIDC_ISSUER']
            if not issuer.startswith('https://'):
                raise ValueError('OIDC issuer must use HTTPS')
            request = urllib.request.Request(issuer + '/protocol/openid-connect/certs',
                                             headers={'User-Agent': 'CloudLab-Notes/1.0'})
            opener = urllib.request.build_opener(NoRedirect())
            with opener.open(request, timeout=5) as response:
                raw = response.read(131073)
            if len(raw) > 131072:
                raise ValueError('Signing key response exceeds limit')
            KEYS.update(document=json.loads(raw), expires=time.time() + 60)
        return KEYS['document']


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def authorize(header, role):
    if not isinstance(header, str) or not header.startswith('Bearer '):
        return 401
    try:
        claims = validated_claims(header[7:], signing_keys(), os.environ['OIDC_ISSUER'],
                                  os.environ['OIDC_AUDIENCE'], 'Bearer')
    except Exception:
        return 401
    roles = claims.get('roles', [])
    if not isinstance(roles, list) or any(not isinstance(r, str) for r in roles) or role not in roles:
        return 403
    return 200


def database():
    import psycopg
    directory = os.environ.get('DATABASE_SECRETS', '/secrets/database')
    return psycopg.connect(host=os.environ['PGHOST'], dbname=os.environ['PGDATABASE'],
                           user=credential(directory, 'username'), password=credential(directory, 'password'),
                           sslmode='verify-full', sslrootcert=os.environ['PGSSLROOTCERT'], connect_timeout=5,
                           options='-c statement_timeout=5000 -c lock_timeout=2000')


def objects():
    directory = os.environ.get('S3_SECRETS', '/secrets/objects')
    return S3(credential(directory, 'ENDPOINT'), credential(directory, 'ACCESS_KEY_ID'),
              credential(directory, 'SECRET_ACCESS_KEY'), credential(directory, 'REGION'))


class Handler(BaseHTTPRequestHandler):
    server_version = 'CloudLab'

    def log_message(self, *args):
        pass

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def respond(self, status, value):
        body = json.dumps(value).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            if self.path == '/live':
                return self.respond(200, {'live': True})
            if self.path == '/ready':
                with telemetry.dependency('database'), database() as connection:
                    connection.execute('SELECT 1 FROM public.notes LIMIT 1')
                bucket = credential(os.environ.get('S3_SECRETS', '/secrets/objects'), 'BUCKET')
                with telemetry.dependency('objects'):
                    objects().request('HEAD', bucket)
                return self.respond(200, {'ready': True})
            role = 'operator' if self.path == '/api/operations' else 'reader'
            if self.path == '/api/operations' and self.headers.get('Host') != os.environ.get('OPERATIONS_HOST'):
                return self.respond(404, {'error': 'not found'})
            status = authorize(self.headers.get('Authorization'), role)
            if status != 200:
                return self.respond(status, {'error': 'unauthorized' if status == 401 else 'forbidden'})
            if self.path in ('/api/notes', '/api/release/notes'):
                with telemetry.dependency('database'), database() as connection:
                    rows = connection.execute('SELECT id, title, body, attachment_key FROM public.notes ORDER BY id LIMIT 100').fetchall()
                return self.respond(200, {'notes': [dict(zip(('id', 'title', 'body', 'attachment'), row)) for row in rows]})
            if self.path == '/api/operations':
                return self.respond(200, {'service': 'notes-api', 'dataPolicy': 'retain'})
            return self.respond(404, {'error': 'not found'})
        except Exception:
            return self.respond(503, {'error': 'dependency unavailable'})

    def do_POST(self):
        status = authorize(self.headers.get('Authorization'), 'writer')
        if status != 200:
            return self.respond(status, {'error': 'unauthorized' if status == 401 else 'forbidden'})
        if self.path != '/api/notes':
            return self.respond(404, {'error': 'not found'})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 1 <= length <= MAX_BODY or self.headers.get('Transfer-Encoding'):
                return self.respond(413, {'error': 'body size'})
            value = json.loads(self.rfile.read(length))
            if (not isinstance(value, dict) or set(value) != {'id', 'title', 'body'} or
                    not isinstance(value['id'], str) or not re.fullmatch(r'[a-z0-9-]{1,40}', value['id']) or
                    not isinstance(value['title'], str) or not 1 <= len(value['title']) <= 120 or
                    not isinstance(value['body'], str) or not 1 <= len(value['body']) <= 8192):
                return self.respond(400, {'error': 'invalid note'})
            # Immutable content keys make retries safe. Failed SQL leaves an orphan,
            # never a row referencing overwritten/missing attachment content.
            raw = value['body'].encode()
            key = 'notes/' + hashlib.sha256(raw).hexdigest() + '.txt'
            bucket = credential(os.environ.get('S3_SECRETS', '/secrets/objects'), 'BUCKET')
            with telemetry.dependency('objects'):
                objects().request('PUT', bucket, key, data=raw)
            with telemetry.dependency('database'), database() as connection:
                connection.execute('INSERT INTO public.notes(id,title,body,attachment_key) VALUES (%s,%s,%s,%s) '
                                   'ON CONFLICT(id) DO UPDATE SET title=excluded.title,body=excluded.body,attachment_key=excluded.attachment_key',
                                   (value['id'], value['title'], value['body'], key))
            return self.respond(200, {'id': value['id'], 'attachment': key})
        except (ValueError, UnicodeDecodeError):
            return self.respond(400, {'error': 'invalid body'})
        except Exception:
            return self.respond(503, {'error': 'dependency unavailable'})


if __name__ == '__main__':
    telemetry.start('notes-api')
    telemetry.instrument(Handler, 'notes-api')
    server = ThreadingHTTPServer(('0.0.0.0', 8080), Handler)
    server.daemon_threads = True
    server.serve_forever()
