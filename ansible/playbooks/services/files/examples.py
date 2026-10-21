"""Prepare the working Notes definition without provisioning disposable services."""
import copy
import json
import os
from pathlib import Path
import subprocess

from dotenv import dotenv_values
import yaml

from playbooks.secrets.files.vault import fields
from playbooks.access.files.cloudflare import API
from playbooks.services.files.contract import ROOT, validate


def definitions(zone, public_repository, revision, database, bucket):
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
    validate(notes)
    approval = lambda name, repo, visibility, path: {
        'name':name,'namespace':'cloudlab-app-'+name,'repository':repo,'revision':revision,
        'valuesPath':path,'secretReferences':[],'configMaps':[],'visibility':visibility}
    notes_approval = approval('notes', public_repository, 'public', 'apps/notes/values.yaml')
    notes_approval.update(chartPath='apps/notes',secretReferences=['notes-database','notes-objects'],configMaps=['notes-source','database-ca'])
    grants = {
        'notes-database':{'kind':'database','service':'notes','name':database,'item':'cnpg-notes-production','migrationItem':'cnpg-notes-migration'},
        'notes-objects':{'kind':'bucket','service':'notes','name':bucket,'item':'s3-notes-production'}}
    return {'catalog':[{'definition':notes,'approval':notes_approval,'publication':'ready'}], 'dataApprovals':grants}


def prepare():
    environment = dotenv_values(ROOT / '.env', interpolate=False)
    os.environ['OP_SERVICE_ACCOUNT_TOKEN'] = environment.get('OP_SERVICE_ACCOUNT_TOKEN') or ''
    credentials = fields('cloudlab-dns01', ('API_TOKEN','ZONE_ID'))
    zone = API(credentials['API_TOKEN']).request('GET', 'zones/'+credentials['ZONE_ID'])
    if zone.get('id') != credentials['ZONE_ID'] or zone.get('status') != 'active': raise RuntimeError('Existing active DNS zone required')
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
    revision = subprocess.check_output(['git','-c','safe.directory=/workspace','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    database = fields('cnpg-notes-production', ('database',))['database']
    bucket = fields('s3-notes-production', ('BUCKET',))['BUCKET']
    value = definitions(zone['name'], public, revision, database, bucket)
    base = Path('/recovery/services')
    base.mkdir(mode=0o700,parents=True,exist_ok=True)
    for entry in value['catalog']:
        filename = base / (entry['definition']['name']+'.json')
        filename.write_text(json.dumps(entry['definition'],sort_keys=True))
        filename.chmod(0o600)
    destination = base / 'catalog-proposal.json'
    destination.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    destination.chmod(0o600)
    return {'prepared':True,'private_output':str(destination),'live_mutations':0}


def bundles(value):
    from playbooks.services.files.inputs import validate_catalog
    value = validate_catalog(copy.deepcopy(value))
    public = yaml.safe_load((ROOT / 'gitops/roots/public/values.yaml').read_text())['repository']
    revision = subprocess.check_output(['git','-c','safe.directory=/workspace','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
    origin = json.loads((ROOT / 'platform/connectivity/access/contract.json').read_text())['cloudflareOrigin']
    target = Path('/recovery/services')
    target.mkdir(mode=0o700,parents=True,exist_ok=True)
    for entry in value['catalog']:
        bundle = {'definition':entry['definition'],'approval':entry['approval'],
                  'platformRepository':public,'platformRevision':revision,'origin':origin,'application':None}
        filename = target / (entry['definition']['name']+'-bundle.json')
        filename.write_text(json.dumps(bundle,sort_keys=True))
        filename.chmod(0o600)
    proposal = target / 'catalog-proposal.json'
    proposal.write_text(json.dumps(value,sort_keys=True,indent=2)+'\n')
    proposal.chmod(0o600)
    return {'prepared_bundles':len(value['catalog']),'private_output':str(proposal),'secret_values_logged':False}
