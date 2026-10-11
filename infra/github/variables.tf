variable "owner" { type = string }
variable "repositories" {
  type = map(object({
    name                        = string
    description                 = string
    visibility                  = string
    default_branch              = string
    has_issues                  = bool
    has_projects                = bool
    has_wiki                    = bool
    has_discussions             = bool
    allow_merge_commit          = bool
    allow_squash_merge          = bool
    allow_rebase_merge          = bool
    allow_auto_merge            = bool
    delete_branch_on_merge      = bool
    web_commit_signoff_required = bool
  }))
  validation {
    condition = length(var.repositories) > 0 && alltrue([for key, repo in var.repositories :
      can(regex("^[a-z][a-z0-9_-]*$", key)) && contains(["public", "private"], repo.visibility)
    ])
    error_message = "Supply every designated existing repository using stable logical keys."
  }
}
variable "rulesets" {
  type = map(object({
    repository              = string
    name                    = string
    include                 = list(string)
    exclude                 = list(string)
    bypass_actors           = list(object({ actor_id = number, actor_type = string, bypass_mode = string }))
    deletion                = bool
    non_fast_forward        = bool
    required_linear_history = bool
    pull_request = object({
      allowed_merge_methods             = list(string)
      dismiss_stale_reviews_on_push     = bool
      require_code_owner_review         = bool
      require_last_push_approval        = bool
      required_approving_review_count   = number
      required_review_thread_resolution = bool
    })
    strict_status_checks = bool
    status_checks        = list(object({ context = string, integration_id = optional(number) }))
  }))
  validation {
    condition = alltrue([for key, rule in var.rulesets :
      can(regex("^[a-z][a-z0-9_-]*$", key)) && contains(keys(var.repositories), rule.repository) && length(rule.include) > 0
    ])
    error_message = "Rulesets must reference designated repositories with explicit branch scope."
  }
}
