"""Disposable retirement proof; observations remain in memory, owners retain state."""
from automation.services.lifecycle import ready, publish, retire


def run(bundle):
    from playbooks.data.files.service_proof import fixture
    from automation.services.owners import Owners
    fixture({'definition': bundle['definition'], 'approval': bundle['approval']})
    owners = Owners(bundle)
    ready(bundle['definition'], owners)
    before = owners.read('fixture-snapshot')
    owners.read('fixture-data')
    publish(bundle['definition'], owners)
    # Repeat the completed publication: preserve credentials and observed owners.
    publish(bundle['definition'], owners)
    retire(bundle['definition'], owners)
    after = owners.read('fixture-snapshot')
    if before != after:
        raise RuntimeError('Retirement changed retained credentials, data or shared identities')
    owners.read('fixture-data')
    owners.read('fixture-volume')
    return {'publication_rerun': True, 'reachability_withdrawn': True,
            'retained_sql_s3_and_volume': True, 'shared_identities_preserved': True}
