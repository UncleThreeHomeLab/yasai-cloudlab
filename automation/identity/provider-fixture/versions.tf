terraform {
  required_version = "= 1.13.1"
  required_providers {
    keycloak = {
      source  = "keycloak/keycloak"
      version = "= 5.10.0"
    }
  }
}
