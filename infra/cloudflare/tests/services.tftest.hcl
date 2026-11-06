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

run "service_protected_application" {
  command = apply
  variables {
    applications = merge(jsondecode(file("fixtures.json")).applications, {
      service_synthetic = {
        name                      = "synthetic-service"
        domain                    = "service.example.invalid"
        session_duration          = "1h"
        allowed_idps              = []
        app_launcher_visible      = false
        auto_redirect_to_identity = false
        enable_binding_cookie     = false
        options_preflight_bypass  = false
        policies = {
          allow_machine = {
            id         = "00000000-0000-4000-8000-000000000008"
            name       = "synthetic-machine"
            decision   = "non_identity"
            precedence = 1
            include    = [{ service_token = { token_id = "00000000-0000-4000-8000-000000000005" } }]
            exclude    = []
            require    = []
          }
        }
      }
    })
    service_exposures = {
      service_synthetic = {
        exposure    = { class = "public", hostname = "service.example.invalid", access = "machine", path = "/", port = 8080 }
        origin      = "https://origin.example.invalid"
        application = "service_synthetic"
        routed      = true
        published   = true
      }
    }
  }
  assert {
    condition     = length(cloudflare_zero_trust_access_application.service_application) == 1
    error_message = "Compiled service applications must use the destroyable service resource."
  }
  assert {
    condition     = length(cloudflare_zero_trust_access_application.application) == 1
    error_message = "Base applications must stay under destroy protection."
  }
  assert {
    condition     = cloudflare_dns_record.service_publication["service_synthetic"].name == "service.example.invalid"
    error_message = "Protected service publication must consume the exposure hostname."
  }
}

run "service_retirement_destroys" {
  command = apply
  variables {
    applications      = jsondecode(file("fixtures.json")).applications
    service_exposures = {}
  }
  assert {
    condition     = length(cloudflare_zero_trust_access_application.service_application) == 0
    error_message = "Retired service applications must destroy without residue."
  }
  assert {
    condition     = length(cloudflare_zero_trust_access_application.application) == 1
    error_message = "Retirement must leave base applications untouched."
  }
  assert {
    condition     = length(cloudflare_zero_trust_tunnel_cloudflared_config.routing.config.ingress) == length(var.routes) + 1
    error_message = "Retirement must withdraw tunnel reachability."
  }
}
