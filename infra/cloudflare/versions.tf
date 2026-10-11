terraform {
  required_version = "= 1.13.1"
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "= 5.27.0"
    }
  }
  backend "http" {}
  encryption {
    state { enforced = true }
    plan { enforced = true }
  }
}

provider "cloudflare" {}

provider "cloudflare" {
  alias     = "dns"
  api_token = var.dns_api_token
}
