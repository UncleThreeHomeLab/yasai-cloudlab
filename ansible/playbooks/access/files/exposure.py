"""Validate public exposure declarations and compile native service inputs.

Public file services/exposures.yaml is the single source for public hostnames
and access: one entry per service, keyed by service name. Hostnames must be
unique across entries and legacy routes, and can never take over private,
ACME, or foreign names. DNS publication additionally requires a live route, a
ready certificate, and its resolved protection.
"""
import json
from pathlib import Path
import re
import uuid

import yaml
from jsonschema import validate

ROOT = Path(__file__).resolve().parents[4]
SCHEMA = ROOT / 'infra/cloudflare/exposures.schema.json'
APPROVAL_SCHEMA = ROOT / 'platform/connectivity/access/approval.schema.json'
CONTRACT = ROOT / 'platform/connectivity/access/contract.json'

# Stable namespace so compiled policy identities survive recompilation.
APPLICATION_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, 'https://cloudlab.invalid/cloudflare-access')


def origin():
    return json.loads(CONTRACT.read_text())['cloudflareOrigin']


def session_duration():
    return json.loads(CONTRACT.read_text())['sessionDuration']


def validate_bundle(text, zone):
    """Schema plus key, zone, and boundary checks; returns service documents."""
    if len(text.encode()) > 65536:
        raise ValueError('Exposure declarations exceed their bound')
    document = yaml.safe_load(text)
    validate(document, json.loads(SCHEMA.read_text()))
    entries = document['exposures']
    for key in sorted(entries):
        entry = entries[key]
        if entry['service'] != key:
            raise ValueError('Exposure entry key must match its service name')
        hostname = entry['exposure']['hostname']
        if 'internal' in hostname.split('.') or '_acme-challenge' in hostname.split('.'):
            raise ValueError('Service exposure must not take over private or ACME names')
        if not hostname.endswith('.' + zone) or hostname == zone:
            raise ValueError('Service exposure must stay inside the declared zone')
        if hostname.split('.')[0] != key:
            raise ValueError('Service exposure cannot take over another hostname')
    return [entries[key] for key in sorted(entries)]


def validate_approval(text, revision):
    """Returns True only when the merged binding approves this exact revision.

    A missing binding is normal (nothing approved yet); a malformed binding is
    an author error and fails loudly. Stale bindings never apply.
    """
    document = yaml.safe_load(text)
    validate(document, json.loads(APPROVAL_SCHEMA.read_text()))
    return document['revision'] == revision, document['plan']


def service_key(service):
    key = 'service_' + service.replace('-', '_')
    if not re.fullmatch(r'service_[a-z][a-z0-9_]*', key):
        raise ValueError('Service exposure key is invalid')
    return key


def application_intent(document, *, human_email, identity_provider, service_token_id):
    """Fixed-template Access application for one protected hostname."""
    exposure = document['exposure']
    hostname = exposure['hostname']
    key = service_key(document['service'])
    if exposure['access'] == 'public':
        return None
    if exposure['access'] == 'human':
        if not human_email or '@' not in human_email or not identity_provider:
            raise ValueError('Human exposure requires an approved email and identity provider')
        policies = {'allow_human': {
            'id': str(uuid.uuid5(APPLICATION_NAMESPACE, 'allow:' + hostname)),
            'name': 'cloudlab-human', 'decision': 'allow', 'precedence': 1,
            'include': [{'email': {'email': human_email}}], 'exclude': [],
            'require': [{'login_method': {'id': identity_provider}}]}}
        allowed = [identity_provider]
    else:
        if not service_token_id:
            raise ValueError('Machine exposure requires a pre-provisioned service token')
        policies = {'allow_machine': {
            'id': str(uuid.uuid5(APPLICATION_NAMESPACE, 'machine:' + hostname)),
            'name': 'cloudlab-machine', 'decision': 'non_identity', 'precedence': 1,
            'include': [{'service_token': {'token_id': service_token_id}}],
            'exclude': [], 'require': []}}
        allowed = []
    return {'name': 'cloudlab-' + hostname.split('.')[0], 'domain': hostname,
            'session_duration': session_duration(), 'allowed_idps': allowed,
            'app_launcher_visible': False,
            'auto_redirect_to_identity': exposure['access'] == 'human',
            'enable_binding_cookie': False, 'options_preflight_bypass': False,
            'policies': policies, '_key': key}


def compile_service_exposures(documents, legacy_routes, *, human_email=None,
                              identity_provider=None, service_token_id=None):
    """Published entries to native tfvars; retired entries withdraw without residue."""
    hostnames = [route['hostname'] for route in legacy_routes.values()]
    compiled, applications = {}, {}
    for document in sorted(documents, key=lambda row: row['service']):
        exposure = document['exposure']
        if exposure['hostname'] in hostnames:
            raise ValueError('Service exposure must not take over another declared hostname')
        hostnames.append(exposure['hostname'])
        if document['publication'] != 'published':
            continue
        key = service_key(document['service'])
        intent = application_intent(document, human_email=human_email,
                                    identity_provider=identity_provider,
                                    service_token_id=service_token_id)
        compiled[key] = {
            'exposure': {field: exposure[field]
                         for field in ('class', 'hostname', 'access', 'path', 'port')},
            'origin': origin(), 'application': intent['_key'] if intent else None,
            'routed': True, 'published': True}
        if intent:
            intent = dict(intent)
            applications[intent.pop('_key')] = intent
    return {'service_exposures': compiled, 'applications': applications}
