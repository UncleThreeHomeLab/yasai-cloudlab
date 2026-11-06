locals {
  governance = yamldecode(file("${path.module}/${var.governance_file}"))
  profile    = local.governance.governance
  permissions = var.import_permissions == null ? {
    public_platform = {
      default_workflow_permissions     = local.profile.workflowTokenPermissions == "read-only" ? "read" : "unsupported"
      can_approve_pull_request_reviews = local.profile.workflowsMayApprovePullRequests
    }
    private_config = var.private_permissions
  } : var.import_permissions
}

resource "terraform_data" "governance" {
  input = local.governance
  lifecycle {
    precondition {
      condition     = var.import_permissions != null || local.profile.profile == "public-gitops"
      error_message = "Unsupported governance profile; only the reviewed public-gitops profile is supported."
    }
    precondition {
      condition     = var.import_permissions != null || local.profile.workflowTokenPermissions == "read-only"
      error_message = "Workflow token permissions must stay read-only; no other workflow default is supported."
    }
    precondition {
      condition     = var.import_permissions != null || local.profile.workflowsMayApprovePullRequests == false
      error_message = "Workflows must not approve pull requests; no approval grant is supported."
    }
    precondition {
      condition     = var.import_permissions != null || local.profile.releaseAppsMayMerge == false
      error_message = "Release Apps must not merge; proposer and merge authority stay separated by the merge guard."
    }
    precondition {
      condition     = var.import_permissions != null || local.profile.forcePushes == false
      error_message = "Force pushes must stay forbidden; enforcement is owned by repository rulesets and is never weakened here."
    }
    precondition {
      condition     = var.import_permissions != null || local.profile.branchDeletion == false
      error_message = "Branch deletion must stay forbidden; enforcement is owned by repository rulesets and is never weakened here."
    }
    precondition {
      condition     = var.import_permissions != null || local.profile.reviewBoundary == "public-pr-merge-guard"
      error_message = "Unsupported review boundary; governance merges require the public PR merge-guard boundary."
    }
    precondition {
      condition = var.import_permissions != null || (local.governance.repository == "${var.owner}/${var.repositories["public_platform"].name}" &&
      local.governance.repositoryId == var.repositories["public_platform"].id)
      error_message = "Governance declaration does not bind the approved public repository identity."
    }
    precondition {
      condition = var.import_permissions != null || (toset(keys(local.governance)) == toset(["repository", "repositoryId", "governance"]) &&
        toset(keys(local.profile)) == toset(["profile", "workflowTokenPermissions", "workflowsMayApprovePullRequests",
      "releaseAppsMayMerge", "forcePushes", "branchDeletion", "reviewBoundary"]))
      error_message = "Unsupported governance field; only the reviewed profile fields are supported."
    }
    precondition {
      condition     = var.import_permissions != null || var.enable_merge_guard
      error_message = "Merge guard disabled while release Apps must not merge; refusing to lower the review boundary."
    }
  }
}

resource "github_workflow_repository_permissions" "release" {
  depends_on                       = [terraform_data.governance]
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

output "unsupported_prerequisites" {
  value = [
    "Review boundary '${local.profile.reviewBoundary}': enforced by repository rulesets and the merge guard, not by this module.",
    "Force-push and branch-deletion protection: owned by repository rulesets (infra/github); verify there, never weakened here.",
    "GitHub App installation, repository visibility changes, and expanded grants: explicit prerequisites, never auto-enabled.",
    "Provider apply: requires separately authorized scoped execution; merges declare intent only.",
  ]
}
