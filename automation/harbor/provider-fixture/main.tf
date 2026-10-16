variable "robot_secret" {
  type      = string
  sensitive = true
  ephemeral = true
}

provider "harbor" {
  insecure     = false
  robot_prefix = "robot$"
}

resource "harbor_robot_account" "fixture" {
  name              = "custody"
  description       = "Disposable custody qualification"
  level             = "project"
  duration          = -1
  secret_wo         = var.robot_secret
  secret_wo_version = 1
  permissions {
    kind      = "project"
    namespace = "custody-fixture"
    access {
      action   = "pull"
      resource = "repository"
      effect   = "allow"
    }
  }
  lifecycle {
    prevent_destroy = true
  }
}
