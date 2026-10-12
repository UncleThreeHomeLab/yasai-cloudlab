mock_provider "cloudflare" {}
mock_provider "cloudflare" { alias = "dns" }

variables {
  dns_api_token = "synthetic-only"
  account_id    = jsondecode(file("fixtures.json")).account_id
  zone_id       = jsondecode(file("fixtures.json")).zone_id
  tunnel_id     = jsondecode(file("fixtures.json")).tunnel_id
  team_name     = jsondecode(file("fixtures.json")).team_name
  applications  = jsondecode(file("fixtures.json")).applications
  routes        = jsondecode(file("fixtures.json")).routes
}

run "service_ready_closed" {
  command = plan
  variables {
    service_exposures = {
      service_synthetic = {
        exposure  = { class = "public", hostname = "service.example.invalid", access = "public", path = "/", port = 8080 }
        origin    = "https://origin.example.invalid"
        routed    = false
        published = false
      }
    }
  }
  assert {
    condition     = length(cloudflare_dns_record.service_publication) == 0
    error_message = "Ready intent must not publish DNS."
  }
  assert {
    condition     = length(cloudflare_zero_trust_tunnel_cloudflared_config.routing.config.ingress) == length(var.routes) + 1
    error_message = "Ready intent must not add tunnel reachability."
  }
}

run "service_publish_after_routing" {
  command = plan
  variables {
    service_exposures = {
      service_synthetic = {
        exposure  = { class = "public", hostname = "service.example.invalid", access = "public", path = "/", port = 8080 }
        origin    = "https://origin.example.invalid"
        routed    = true
        published = true
      }
    }
  }
  assert {
    condition     = cloudflare_dns_record.service_publication["service_synthetic"].name == var.service_exposures.service_synthetic.exposure.hostname
    error_message = "DNS must consume the same exposure hostname."
  }
  assert {
    condition     = cloudflare_zero_trust_tunnel_cloudflared_config.routing.config.ingress[length(var.routes)].hostname == var.service_exposures.service_synthetic.exposure.hostname
    error_message = "Tunnel routing must consume the same exposure hostname."
  }
}

run "reject_publication_before_routing" {
  command = plan
  variables {
    service_exposures = {
      service_synthetic = {
        exposure  = { class = "public", hostname = "service.example.invalid", access = "public", path = "/", port = 8080 }
        origin    = "https://origin.example.invalid"
        routed    = false
        published = true
      }
    }
  }
  expect_failures = [var.service_exposures]
}

run "reject_private_input_in_public_root" {
  command = plan
  variables {
    service_exposures = {
      service_synthetic = {
        exposure  = { class = "private", hostname = "service.internal.example.invalid", access = "tailnet", path = "/", port = 8080 }
        origin    = "https://origin.example.invalid"
        routed    = false
        published = false
      }
    }
  }
  expect_failures = [var.service_exposures]
}
