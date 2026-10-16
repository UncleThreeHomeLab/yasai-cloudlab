terraform {
  required_version = "= 1.13.1"
  required_providers {
    harbor = {
      source  = "goharbor/harbor"
      version = "= 3.12.5"
    }
  }
}
