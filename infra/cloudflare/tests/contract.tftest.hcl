mock_provider "cloudflare" {}
mock_provider "cloudflare" { alias = "dns" }

run "synthetic_contract" {
  command = plan
  variables {
    dns_api_token = "synthetic-only"
    account_id    = jsondecode(file("fixtures.json")).account_id
    zone_id       = jsondecode(file("fixtures.json")).zone_id
    tunnel_id     = jsondecode(file("fixtures.json")).tunnel_id
    team_name     = jsondecode(file("fixtures.json")).team_name
    applications  = jsondecode(file("fixtures.json")).applications
    routes        = jsondecode(file("fixtures.json")).routes
  }
  assert {
    condition     = cloudflare_dns_record.publication["fixture"].proxied
    error_message = "Public fixture must use the protected tunnel publication."
  }
  assert {
    condition     = cloudflare_zero_trust_access_application.application["fixture"].policies[0].precedence == 1
    error_message = "Policy precedence must not depend on logical key ordering."
  }
  assert {
    condition     = cloudflare_zero_trust_access_application.application["fixture"].policies[0].id == jsondecode(file("fixtures.json")).applications.fixture.policies.z_human.id
    error_message = "Legacy policy updates must retain the designated existing policy ID."
  }
  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.routing.config.ingress[0].origin_request.access.required && length(cloudflare_zero_trust_tunnel_cloudflared_config.routing.config.ingress[0].origin_request.access.aud_tag) == 1
    error_message = "Protected routes must require the application audience at the origin."
  }
  assert {
    condition     = !cloudflare_zero_trust_tunnel_cloudflared_config.routing.config.ingress[0].origin_request.no_tls_verify
    error_message = "Origin TLS verification must remain enabled."
  }
  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.routing.config.ingress[length(cloudflare_zero_trust_tunnel_cloudflared_config.routing.config.ingress) - 1].service == "http_status:404"
    error_message = "Unknown hosts must end at the terminal deny route."
  }
}
