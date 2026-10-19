mock_provider "github" {}

variables {
  owner = "example"
  repositories = {
    public_platform = { name = "public-gitops", id = 100, node_id = "R_public" }
    private_config  = { name = "private-gitops", id = 101, node_id = "R_private" }
  }
}

run "scoped_release_permissions" {
  command = plan
  assert {
    condition = length(github_workflow_repository_permissions.release) == 2 && alltrue([
      for permissions in github_workflow_repository_permissions.release :
      permissions.default_workflow_permissions == "read" && permissions.can_approve_pull_request_reviews
    ])
    error_message = "Only two repository receivers may open PRs; default workflow permissions remain read-only."
  }
}

run "creation_free_import_preserves_current_fields" {
  command = plan
  variables {
    import_permissions = {
      public_platform = { default_workflow_permissions = "read", can_approve_pull_request_reviews = false }
      private_config  = { default_workflow_permissions = "write", can_approve_pull_request_reviews = false }
    }
  }
  assert {
    condition = (!github_workflow_repository_permissions.release["public_platform"].can_approve_pull_request_reviews &&
    github_workflow_repository_permissions.release["private_config"].default_workflow_permissions == "write")
    error_message = "Import must preserve current fields before the reviewed policy is applied."
  }
}
