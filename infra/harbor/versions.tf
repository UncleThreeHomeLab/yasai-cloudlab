terraform {
  required_version = "= 1.13.0"
  required_providers {
    harbor = {
      source  = "cloudlab/harbor"
      version = "= 3.12.5-cloudlab.2"
    }
  }
  backend "http" {}
  encryption {
    state { enforced = true }
    plan { enforced = true }
  }
}

provider "harbor" {
  insecure     = false
  robot_prefix = "robot$"
}
