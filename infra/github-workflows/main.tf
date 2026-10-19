locals {
  permissions = var.import_permissions == null ? jsondecode(file("policy.json")) : var.import_permissions
}

resource "github_workflow_repository_permissions" "release" {
  for_each                         = var.repositories
  repository                       = each.value.name
  default_workflow_permissions     = local.permissions[each.key].default_workflow_permissions
  can_approve_pull_request_reviews = local.permissions[each.key].can_approve_pull_request_reviews
  lifecycle { prevent_destroy = true }
}

output "repository_identities" {
  value = { for key, repository in var.repositories : key => {
    id = repository.id, node_id = repository.node_id
  } }
}
