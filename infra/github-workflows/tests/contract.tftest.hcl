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
    condition = (github_repository_ruleset.tag_guard[0].rules[0].creation &&
      github_repository_ruleset.tag_guard[0].rules[0].update && github_repository_ruleset.tag_guard[0].rules[0].deletion &&
      github_repository_ruleset.tag_guard[0].bypass_actors[0].actor_id == 5 &&
    github_repository_ruleset.tag_guard[0].conditions[0].ref_name[0].include == tolist(["~ALL"]))
    error_message = "Only repository administrators may mutate tags, including names shadowing GitOps branches."
  }
  assert {
    condition = (github_repository_ruleset.merge_guard[0].rules[0].update &&
      github_repository_ruleset.merge_guard[0].bypass_actors[0].actor_id == 5 &&
      github_repository_ruleset.merge_guard[0].bypass_actors[0].bypass_mode == "pull_request" &&
      github_repository_ruleset.merge_guard[0].repository == "public-gitops")
    error_message = "Release Apps cannot merge; only repository admins can update main through a PR."
  }
  assert {
    condition = length(github_workflow_repository_permissions.release) == 2 && alltrue([
      for permissions in github_workflow_repository_permissions.release :
      permissions.default_workflow_permissions == "read" && !permissions.can_approve_pull_request_reviews
    ])
    error_message = "Workflow tokens stay read-only and cannot approve PRs; scoped release Apps own proposals."
  }
}

run "creation_free_import_preserves_current_fields" {
  command = plan
  variables {
    enable_merge_guard = false
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
