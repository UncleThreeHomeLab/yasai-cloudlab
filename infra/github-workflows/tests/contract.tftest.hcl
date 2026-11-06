mock_provider "github" {}

variables {
  owner = "example"
  repositories = {
    public_platform = { name = "public-gitops", id = 100, node_id = "R_public" }
    private_config  = { name = "private-gitops", id = 101, node_id = "R_private" }
  }
  private_permissions = { default_workflow_permissions = "read", can_approve_pull_request_reviews = false }
}

run "scoped_release_permissions" {
  command = plan
  variables {
    governance_file = "tests/fixtures/governance-ok.yaml"
  }
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
  assert {
    condition     = length(output.unsupported_prerequisites) == 4
    error_message = "Every plan must report the standing unsupported prerequisites."
  }
}

run "tracked_platform_declaration_converges" {
  command = plan
  variables {
    owner = "UncleThreeHomeLab"
    repositories = {
      public_platform = { name = "yasai-cloudlab", id = 1401562816, node_id = "R_kgDOU4omwA" }
      private_config  = { name = "synthetic-private", id = 1, node_id = "R_synthetic" }
    }
  }
  assert {
    condition = (github_workflow_repository_permissions.release["public_platform"].default_workflow_permissions == "read" &&
      !github_workflow_repository_permissions.release["public_platform"].can_approve_pull_request_reviews &&
    output.repository_identities["public_platform"].id == 1401562816)
    error_message = "Tracked platform governance must bind the real repository with read-only workflow tokens."
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

run "refuse_unsupported_profile" {
  command = plan
  variables {
    governance_file = "tests/fixtures/governance-bad-profile.yaml"
  }
  expect_failures = [terraform_data.governance]
}

run "refuse_write_tokens" {
  command = plan
  variables {
    governance_file = "tests/fixtures/governance-write-tokens.yaml"
  }
  expect_failures = [terraform_data.governance]
}

run "refuse_workflow_approvals" {
  command = plan
  variables {
    governance_file = "tests/fixtures/governance-approve-prs.yaml"
  }
  expect_failures = [terraform_data.governance]
}

run "refuse_release_app_merge" {
  command = plan
  variables {
    governance_file = "tests/fixtures/governance-apps-merge.yaml"
  }
  expect_failures = [terraform_data.governance]
}

run "refuse_force_pushes" {
  command = plan
  variables {
    governance_file = "tests/fixtures/governance-force-pushes.yaml"
  }
  expect_failures = [terraform_data.governance]
}

run "refuse_branch_deletion" {
  command = plan
  variables {
    governance_file = "tests/fixtures/governance-branch-deletion.yaml"
  }
  expect_failures = [terraform_data.governance]
}

run "refuse_unknown_field" {
  command = plan
  variables {
    governance_file = "tests/fixtures/governance-unknown-field.yaml"
  }
  expect_failures = [terraform_data.governance]
}

run "refuse_identity_mismatch" {
  command = plan
  variables {
    governance_file = "tests/fixtures/governance-identity-mismatch.yaml"
  }
  expect_failures = [terraform_data.governance]
}

run "refuse_foreign_review_boundary" {
  command = plan
  variables {
    governance_file = "tests/fixtures/governance-bad-boundary.yaml"
  }
  expect_failures = [terraform_data.governance]
}
