resource "github_repository" "repository" {
  for_each                    = var.repositories
  name                        = each.value.name
  description                 = each.value.description
  visibility                  = each.value.visibility
  archived                    = false
  archive_on_destroy          = false
  auto_init                   = false
  has_issues                  = each.value.has_issues
  has_projects                = each.value.has_projects
  has_wiki                    = each.value.has_wiki
  has_discussions             = each.value.has_discussions
  allow_merge_commit          = each.value.allow_merge_commit
  allow_squash_merge          = each.value.allow_squash_merge
  allow_rebase_merge          = each.value.allow_rebase_merge
  allow_auto_merge            = each.value.allow_auto_merge
  delete_branch_on_merge      = each.value.delete_branch_on_merge
  web_commit_signoff_required = each.value.web_commit_signoff_required
  lifecycle { prevent_destroy = true }
}

resource "github_branch_default" "default" {
  for_each   = var.repositories
  repository = github_repository.repository[each.key].name
  branch     = each.value.default_branch
  lifecycle { prevent_destroy = true }
}

resource "github_repository_ruleset" "ruleset" {
  for_each    = var.rulesets
  repository  = github_repository.repository[each.value.repository].name
  name        = each.value.name
  target      = "branch"
  enforcement = "active"
  conditions {
    ref_name {
      include = each.value.include
      exclude = each.value.exclude
    }
  }
  dynamic "bypass_actors" {
    for_each = each.value.bypass_actors
    content {
      actor_id    = bypass_actors.value.actor_id
      actor_type  = bypass_actors.value.actor_type
      bypass_mode = bypass_actors.value.bypass_mode
    }
  }
  rules {
    deletion                = each.value.deletion
    non_fast_forward        = each.value.non_fast_forward
    required_linear_history = each.value.required_linear_history
    pull_request {
      allowed_merge_methods             = each.value.pull_request.allowed_merge_methods
      dismiss_stale_reviews_on_push     = each.value.pull_request.dismiss_stale_reviews_on_push
      require_code_owner_review         = each.value.pull_request.require_code_owner_review
      require_last_push_approval        = each.value.pull_request.require_last_push_approval
      required_approving_review_count   = each.value.pull_request.required_approving_review_count
      required_review_thread_resolution = each.value.pull_request.required_review_thread_resolution
    }
    dynamic "required_status_checks" {
      for_each = length(each.value.status_checks) == 0 ? [] : [each.value.status_checks]
      content {
        strict_required_status_checks_policy = each.value.strict_status_checks
        dynamic "required_check" {
          for_each = required_status_checks.value
          content {
            context        = required_check.value.context
            integration_id = required_check.value.integration_id
          }
        }
      }
    }
  }
  lifecycle { prevent_destroy = true }
}
