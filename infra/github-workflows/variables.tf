variable "owner" { type = string }

variable "repositories" {
  type = map(object({ name = string, id = number, node_id = string }))
  validation {
    condition = toset(keys(var.repositories)) == toset(["public_platform", "private_config"]) && alltrue([
      for repository in var.repositories : can(regex("^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$", repository.name)) &&
      repository.id > 0 && length(repository.node_id) > 0
    ])
    error_message = "Only the two designated GitOps repository identities may own release workflow permissions."
  }
}

variable "import_permissions" {
  type    = map(object({ default_workflow_permissions = string, can_approve_pull_request_reviews = bool }))
  default = null
  validation {
    condition = var.import_permissions == null ? true : (
      toset(keys(var.import_permissions)) == toset(["public_platform", "private_config"]) &&
      alltrue([for permissions in var.import_permissions : contains(["read", "write"], permissions.default_workflow_permissions)])
    )
    error_message = "Initial import must preserve the complete observed permissions of both GitOps repositories."
  }
}
