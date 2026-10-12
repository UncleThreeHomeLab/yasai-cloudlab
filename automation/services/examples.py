"""Prepare the approved notes and disposable private service definitions."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess

from dotenv import dotenv_values
import yaml

from automation.credentials.vault import fields
from automation.connectivity.cloudflare import API
from automation.services.contract import ROOT, validate


def definitions(zone, public_repository, revision, private_repository, nonce, database, bucket):
    if not re.fullmatch('[a-f0-9]{12}', nonce): raise ValueError('Fixture requires its stable twelve-character nonce')
    base = yaml.safe_load((ROOT / 'apps/synthetic.yaml').read_text())
    notes = copy.deepcopy(base)
    notes.update(name='notes', owner='platform', replicas=2, resources={
        'requests': {'cpu':'50m','memory':'64Mi'}, 'limits':{'cpu':'400m','memory':'384Mi'}},
        exposure={'class':'public','hostname':'notes.'+zone,'access':'public','path':'/','port':8080},
        additionalExposures=[{'class':'private','hostname':'notes.internal.'+zone,'access':'tailnet','path':'/','port':8080}],
        oidc={'enabled':True,'realm':'applications','client':'notes-web','public':True,'audience':'notes-api',
              'callbackPaths':['/callback'],'scopes':['profile','email'],
              'roleMapping':{'reader':['viewer','developer','platform-admin'], 'writer':['developer','platform-admin'], 'operator':['platform-admin']}},
        data={'database':{'name':database,'credentialReference':'notes-database','retention':'retain'},
              'bucket':{'name':bucket,'credentialReference':'notes-objects','retention':'retain'}})
    fixture = copy.deepcopy(base)
    name = 'fixture-' + nonce
    fixture.update(name=name, persistence={'enabled':True,'size':'1Gi','mountPath':'/data','retention':'retain'},
        exposure={'class':'private','hostname':name+'.internal.'+zone,'access':'tailnet','path':'/','port':8080},
        secrets=[{'name':'fixture-database','mountPath':'/secrets/database'},{'name':'fixture-objects','mountPath':'/secrets/objects'}],
        data={'database':{'name':'fixture_'+nonce,'credentialReference':'fixture-database','retention':'retain'},
              'bucket':{'name':name,'credentialReference':'fixture-objects','retention':'retain'}})
    fixture['command'] = ['python','-c', """from pathlib import Path
from http.server import BaseHTTPRequestHandler,HTTPServer
import hashlib,json
path=Path('/data/sentinel')
if not path.exists(): path.write_bytes(b'cloudlab retained service fixture\\n')
class Health(BaseHTTPRequestHandler):
 def log_message(self,*args): pass
 def do_GET(self):
  body=json.dumps({'ready':True,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}).encode()
  self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
HTTPServer(('0.0.0.0',8080),Health).serve_forever()
"""]
    validate(notes)
    validate(fixture)
    approval = lambda name, repo, visibility, path: {
        'name':name,'namespace':'cloudlab-app-'+name,'repository':repo,'revision':revision,
        'valuesPath':path,'secretReferences':[],'configMaps':[],'visibility':visibility}
    notes_approval = approval('notes', public_repository, 'public', 'apps/notes/values.yaml')
    notes_approval.update(chartPath='apps/notes',secretReferences=['notes-database','notes-objects'],configMaps=['notes-source','database-ca'])
    fixture_approval = approval(name, private_repository, 'private', 'apps/'+name+'.yaml')
    fixture_approval['secretReferences'] = ['fixture-database','fixture-objects']
    grants = {
        'notes-database':{'kind':'database','service':'notes','name':database,'item':'cnpg-notes-production','migrationItem':'cnpg-notes-migration'},
        'notes-objects':{'kind':'bucket','service':'notes','name':bucket,'item':'s3-notes-production'},
        'fixture-database':{'kind':'database','service':name,'name':'fixture_'+nonce,'item':'cnpg-'+name+'-production','migrationItem':'cnpg-'+name+'-migration'},
        'fixture-objects':{'kind':'bucket','service':name,'name':name,'item':'s3-'+name+'-production'}}
    return {'catalog':[{'definition':notes,'approval':notes_approval,'publication':'ready'},
                       {'definition':fixture,'approval':fixture_approval,'publication':'ready'}], 'dataApprovals':grants}


def prepare(nonce):
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = environment.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    credentials = fields('cloudlab-dns01', ('API_TOKEN','ZONE_ID'))
    zone = API(credentials['API_TOKEN']).request('GET', 'zones/'+credentials['ZONE_ID'])
    if zone.get('id') != credentials['ZONE_ID'] or zone.get('status') != 'active': raise RuntimeError('Existing active DNS zone required')
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
    revision = subprocess.check_output(['git','-c','safe.directory=/workspace','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    database = fields('cnpg-notes-production', ('database',))['database']
    bucket = fields('s3-notes-production', ('BUCKET',))['BUCKET']
    value = definitions(zone['name'], public, revision, environment.get('PRIVATE_TEST_REPOSITORY'), nonce, database, bucket)
    base = Path('/recovery/services')
    base.mkdir(mode=0o700,parents=True,exist_ok=True)
    for entry in value['catalog']:
        filename = base / (entry['definition']['name']+'.json')
        filename.write_text(json.dumps(entry['definition'],sort_keys=True))
        filename.chmod(0o600)
    destination = base / 'catalog-proposal.json'
    destination.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    destination.chmod(0o600)
    return {'prepared':True,'private_output':str(destination),'fixture_nonce':nonce,'live_mutations':0}


def bundles(value):
    from automation.services.inputs import validate_catalog
    from automation.gitops.github_setup import inputs, repository
    from automation.gitops.private_fixture import prepare_service
    value = validate_catalog(copy.deepcopy(value))
    environment, api = inputs()
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
    revision = subprocess.check_output(['git','-c','safe.directory=/workspace','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    origin = json.loads((ROOT / 'platform/connectivity/access/contract.json').read_text())['cloudflareOrigin']
    target = Path('/recovery/services')
    target.mkdir(mode=0o700,parents=True,exist_ok=True)
    for entry in value['catalog']:
        if entry['approval'].get('visibility') == 'private':
            published = prepare_service(api,environment,entry['definition'])
            entry['approval']['revision'] = published['revision']
            entry['approval']['valuesPath'] = published['values_path']
        bundle = {'definition':entry['definition'],'approval':entry['approval'],
                  'platformRepository':public,'platformRevision':revision,'origin':origin,'application':None}
        filename = target / (entry['definition']['name']+'-bundle.json')
        filename.write_text(json.dumps(bundle,sort_keys=True))
        filename.chmod(0o600)
    proposal = target / 'catalog-proposal.json'
    proposal.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    proposal.chmod(0o600)
    return {'prepared_bundles':len(value['catalog']),'private_output':str(proposal),'secret_values_logged':False}
