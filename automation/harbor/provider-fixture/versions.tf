terraform {
  required_version = "= 1.13.1"
  required_providers {
    harbor = {
      source  = "cloudlab/harbor"
      version = "= 3.12.5-cloudlab.1"
    }
  }
}
