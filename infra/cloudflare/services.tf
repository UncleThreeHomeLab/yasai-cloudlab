variable "service_exposures" {
  description = "Compiled from reviewed service definitions; publish after owner readiness checks."
  type = map(object({
    exposure = object({
      class    = string
      hostname = string
      access   = string
      path     = string
      port     = number
    })
    origin      = string
    application = optional(string)
    routed      = bool
    published   = bool
  }))
  default = {}
  validation {
    condition = alltrue([for key, value in var.service_exposures :
      can(regex("^service_[a-z][a-z0-9_]*$", key)) &&
      value.exposure.class == "public" && !contains(split(".", value.exposure.hostname), "internal") &&
      can(regex("^[a-z0-9][a-z0-9.-]+[a-z0-9]$", value.exposure.hostname)) &&
      can(regex("^https://[a-z0-9.-]+(:443)?$", value.origin)) &&
      contains(["public", "human", "machine"], value.exposure.access) &&
      (value.exposure.access == "public" ? value.application == null :
      try(var.applications[value.application].domain == value.exposure.hostname, false)) &&
      (!value.published || value.routed)
    ])
    error_message = "Service publication requires public exposure, verified TLS, explicit protection and ready routing."
  }
  validation {
    condition = length(distinct(concat(
      [for route in var.routes : route.hostname],
      [for value in var.service_exposures : value.exposure.hostname]
    ))) == length(var.routes) + length(var.service_exposures)
    error_message = "Service exposure must not take over another declared hostname."
  }
}

resource "cloudflare_dns_record" "service_publication" {
  provider   = cloudflare.dns
  for_each   = { for key, value in var.service_exposures : key => value if value.published }
  zone_id    = var.zone_id
  name       = each.value.exposure.hostname
  type       = "CNAME"
  content    = "${var.tunnel_id}.cfargotunnel.com"
  proxied    = true
  ttl        = 1
  comment    = "Managed service exposure"
  depends_on = [cloudflare_zero_trust_tunnel_cloudflared_config.routing]
}
