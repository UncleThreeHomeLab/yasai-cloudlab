locals {
  ordered_policies = { for key, app in var.applications : key => [
    for ordered in sort([for policy_key, policy in app.policies : format("%020d:%s", policy.precedence, policy_key)]) :
    app.policies[split(":", ordered)[1]]
  ] }
}

resource "cloudflare_zero_trust_access_application" "application" {
  for_each                  = var.applications
  account_id                = var.account_id
  name                      = each.value.name
  domain                    = each.value.domain
  type                      = "self_hosted"
  session_duration          = each.value.session_duration
  allowed_idps              = length(each.value.allowed_idps) == 0 ? null : each.value.allowed_idps
  app_launcher_visible      = each.value.app_launcher_visible
  auto_redirect_to_identity = each.value.auto_redirect_to_identity
  enable_binding_cookie     = each.value.enable_binding_cookie
  options_preflight_bypass  = each.value.options_preflight_bypass
  policies = [for policy in local.ordered_policies[each.key] : {
    id         = policy.id
    name       = policy.name
    decision   = policy.decision
    include    = policy.include
    exclude    = length(policy.exclude) == 0 ? null : policy.exclude
    require    = length(policy.require) == 0 ? null : policy.require
    precedence = policy.precedence
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
      }], [for key in sort(keys(var.service_exposures)) : {
      hostname = var.service_exposures[key].exposure.hostname
      service  = var.service_exposures[key].origin
      origin_request = {
        origin_server_name = var.service_exposures[key].exposure.hostname
        http_host_header   = var.service_exposures[key].exposure.hostname
        no_tls_verify      = false
        connect_timeout    = 10
        tls_timeout        = 10
        access = var.service_exposures[key].application == null ? null : {
          required  = true
          team_name = var.team_name
          aud_tag   = [cloudflare_zero_trust_access_application.application[var.service_exposures[key].application].aud]
        }
      }
    } if var.service_exposures[key].routed], [{ service = "http_status:404" }])
  }
  lifecycle { prevent_destroy = true }
}

resource "cloudflare_dns_record" "publication" {
  provider   = cloudflare.dns
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
