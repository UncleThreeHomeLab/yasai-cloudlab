terraform {
  required_version = "= 1.13.0"
  required_providers {
    github = {
      source  = "integrations/github"
      version = "= 6.13.0"
    }
  }
  backend "http" {}
  encryption {
    state { enforced = true }
    plan { enforced = true }
  }
}
provider "github" { owner = var.owner }
