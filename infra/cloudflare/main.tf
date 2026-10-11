locals {
  policies = merge([for app_key, app in var.applications : {
    for policy_key, policy in app.policies : "${app_key}:${policy_key}" => policy
  }]...)
}

resource "cloudflare_zero_trust_access_policy" "policy" {
  for_each   = local.policies
  account_id = var.account_id
  name       = each.value.name
  decision   = each.value.decision
  include    = each.value.include
  exclude    = each.value.exclude
  require    = each.value.require
  # Existing non-reusable IDs must pass account-endpoint import/update certification before handoff.
  lifecycle { prevent_destroy = true }
}

resource "cloudflare_zero_trust_access_application" "application" {
  for_each                  = var.applications
  account_id                = var.account_id
  name                      = each.value.name
  domain                    = each.value.domain
  type                      = "self_hosted"
  session_duration          = each.value.session_duration
  allowed_idps              = each.value.allowed_idps
  app_launcher_visible      = each.value.app_launcher_visible
  auto_redirect_to_identity = each.value.auto_redirect_to_identity
  policies = [for ordered in sort([for key, policy in each.value.policies : format("%020d:%s", policy.precedence, key)]) : {
    id         = cloudflare_zero_trust_access_policy.policy["${each.key}:${split(":", ordered)[1]}"].id
    precedence = each.value.policies[split(":", ordered)[1]].precedence
  }]
  lifecycle { prevent_destroy = true }
}

resource "cloudflare_zero_trust_tunnel_cloudflared_config" "routing" {
  account_id = var.account_id
  tunnel_id  = var.tunnel_id
  source     = "cloudflare"
  config = {
    ingress = concat([for key in sort(keys(var.routes)) : {
      hostname = var.routes[key].hostname
      service  = var.routes[key].service
      origin_request = {
        origin_server_name = var.routes[key].hostname
        http_host_header   = var.routes[key].hostname
        no_tls_verify      = false
        connect_timeout    = 10
        tls_timeout        = 10
        access = var.routes[key].application == null ? null : {
          required  = true
          team_name = var.team_name
          aud_tag   = [cloudflare_zero_trust_access_application.application[var.routes[key].application].aud]
        }
      }
    }], [{ service = "http_status:404" }])
  }
  lifecycle { prevent_destroy = true }
}

resource "cloudflare_dns_record" "publication" {
  for_each   = var.routes
  zone_id    = var.zone_id
  name       = each.value.hostname
  type       = "CNAME"
  content    = "${var.tunnel_id}.cfargotunnel.com"
  proxied    = true
  ttl        = 1
  comment    = each.value.dns_comment
  depends_on = [cloudflare_zero_trust_tunnel_cloudflared_config.routing]
  lifecycle { prevent_destroy = true }
}
