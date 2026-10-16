mock_provider "harbor" {
  mock_resource "harbor_project" { defaults = { id = "/projects/1" } }
  mock_resource "harbor_group" { defaults = { id = "/usergroups/1" } }
}

variables {
  robot_secrets = {
    cloudlab-public-push  = "synthetic-public-push-password-0000000000"
    cloudlab-public-pull  = "synthetic-public-pull-password-0000000000"
    cloudlab-private-push = "synthetic-private-push-password-0000000000"
    cloudlab-private-pull = "synthetic-private-pull-password-0000000000"
  }
}

run "scoped_registry" {
  command = plan
  assert {
    condition     = length(harbor_project.project) == 2 && alltrue([for project in harbor_project.project : !project.public && project.storage_quota == 20 && !project.force_destroy])
    error_message = "Both repository scopes require authenticated projects and bounded storage."
  }
  assert {
    condition     = length(harbor_robot_account.robot) == 4 && alltrue([for robot in harbor_robot_account.robot : robot.level == "project" && robot.secret_wo_version == 1])
    error_message = "Only four project robots with stable vault-owned passwords are permitted."
  }
  assert {
    condition     = alltrue([for key, robot in harbor_robot_account.robot : length(robot.permissions) == 1 && length(one(robot.permissions).access) == (endswith(key, "-pull") ? 1 : 2)])
    error_message = "Pull robots must not acquire push permissions."
  }
  assert {
    condition     = length(harbor_project_member_group.member) == 5 && alltrue([for member in harbor_project_member_group.member : member.type == "oidc"])
    error_message = "Human project membership must use designated OIDC groups."
  }
  assert {
    condition     = alltrue([for policy in harbor_retention_policy.retention : policy.rule[0].always_retain && policy.rule[0].untagged_artifacts])
    error_message = "Unattended deletion is blocked before artifact preservation is accepted."
  }
}

run "missing_robot_custody" {
  command = plan
  variables { robot_secrets = {} }
  expect_failures = [var.robot_secrets]
}
