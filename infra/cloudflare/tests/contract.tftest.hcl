mock_provider "cloudflare" {}

run "synthetic_contract" {
  command = plan
  variables {
    account_id   = jsondecode(file("fixtures.json")).account_id
    zone_id      = jsondecode(file("fixtures.json")).zone_id
    tunnel_id    = jsondecode(file("fixtures.json")).tunnel_id
    team_name    = jsondecode(file("fixtures.json")).team_name
    applications = jsondecode(file("fixtures.json")).applications
    routes       = jsondecode(file("fixtures.json")).routes
  }
  assert {
    condition     = cloudflare_dns_record.publication["fixture"].proxied
    error_message = "Public fixture must use the protected tunnel publication."
  }
  assert {
    condition     = cloudflare_zero_trust_access_application.application["fixture"].policies[0].precedence == 1
    error_message = "Policy precedence must not depend on logical key ordering."
  }
}
