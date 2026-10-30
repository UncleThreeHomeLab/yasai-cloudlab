terraform {
  required_version = "= 1.13.0"
  required_providers {
    postgresql = {
      source  = "cyrilgdn/postgresql"
      version = "= 1.27.0"
    }
  }
}
