variable "enable_merge_guard" {
  type    = bool
  default = true
}

resource "github_repository_ruleset" "merge_guard" {
  count       = var.enable_merge_guard ? 1 : 0
  repository  = var.repositories["public_platform"].name
  name        = "cloudlab-human-release-merge"
  target      = "branch"
  enforcement = "active"
  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }
  # Separate from PR/check rules so operator bypass cannot skip those controls.
  bypass_actors {
    actor_id    = 5
    actor_type  = "RepositoryRole"
    bypass_mode = "pull_request"
  }
  rules { update = true }
  lifecycle { prevent_destroy = true }
}

resource "github_repository_ruleset" "tag_guard" {
  count       = var.enable_merge_guard ? 1 : 0
  repository  = var.repositories["public_platform"].name
  name        = "cloudlab-human-gitops-tags"
  target      = "tag"
  enforcement = "active"
  conditions {
    ref_name {
      include = ["~ALL"]
      exclude = []
    }
  }
  bypass_actors {
    actor_id    = 5
    actor_type  = "RepositoryRole"
    bypass_mode = "always"
  }
  rules {
    creation = true
    update   = true
    deletion = true
  }
  lifecycle { prevent_destroy = true }
}
