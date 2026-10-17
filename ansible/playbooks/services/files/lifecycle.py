"""Small ordered checks; field owners retain their state and reconciliation."""
from playbooks.services.files.contract import validate


def same_exposure(definition, observed):
    exposure = definition['exposure']
    if observed and any(observed.get(field) != exposure.get(field) for field in ('class', 'access', 'hostname')):
        raise ValueError('Exposure change requires an explicit retire/verify/migrate operation')


def ready(definition, owners):
    definition = validate(definition)
    owners.require_private_inputs(definition)
    same_exposure(definition, owners.current_exposure(definition))
    # Each owner checks actual convergence. No new receipt or state engine here.
    owners.identity_ready(definition)
    owners.data_ready(definition)
    owners.backend_ready(definition)
    owners.tls_ready(definition)
    return definition


def publish(definition, owners):
    definition = ready(definition, owners)
    if definition['exposure']['class'] == 'none':
        return
    owners.protection_apply(definition)
    owners.protection_verified(definition)
    owners.routing_apply(definition)
    owners.routing_verified(definition)
    # Recheck before DNS. A tool apply is not a distributed transaction.
    owners.backend_ready(definition)
    owners.tls_ready(definition)
    owners.protection_verified(definition)
    owners.dns_publish(definition)
    owners.reachability_verified(definition)


def retire(definition, owners):
    definition = validate(definition)
    owners.require_private_inputs(definition)
    same_exposure(definition, owners.current_exposure(definition))
    owners.dns_withdraw(definition)
    owners.routing_withdraw(definition)
    owners.unreachable_verified(definition)
    owners.protection_retire(definition)
    owners.identity_retire(definition)
    owners.workload_retire(definition)
    # Namespace, quota, shared resources and application data are never deleted.
    owners.data_retained(definition)
