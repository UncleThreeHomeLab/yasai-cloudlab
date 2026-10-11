variable "dns_api_token" {
  type      = string
  sensitive = true
}
variable "account_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.account_id))
    error_message = "Supply the existing account ID."
  }
}
variable "zone_id" {
  type = string
  validation {
    condition     = can(regex("^[0-9a-f]{32}$", var.zone_id))
    error_message = "Supply the existing zone ID."
  }
}
variable "tunnel_id" { type = string }
variable "team_name" { type = string }
variable "applications" {
  type = map(object({
    name                      = string
    domain                    = string
    session_duration          = string
    allowed_idps              = set(string)
    app_launcher_visible      = bool
    auto_redirect_to_identity = bool
    enable_binding_cookie     = bool
    options_preflight_bypass  = bool
    policies = map(object({
      name       = string
      decision   = string
      precedence = number
      include = list(object({
        email         = optional(object({ email = string }))
        service_token = optional(object({ token_id = string }))
      }))
      exclude = list(object({ email = optional(object({ email = string })) }))
      require = list(object({
        login_method = optional(object({ id = string }))
        oidc = optional(object({
          claim_name           = string
          claim_value          = string
          identity_provider_id = string
        }))
      }))
    }))
  }))
  validation {
    condition = alltrue([for key, app in var.applications :
      can(regex("^[a-z][a-z0-9_-]*$", key)) && length(app.policies) > 0 &&
      length(distinct([for p in app.policies : p.precedence])) == length(app.policies) &&
      alltrue([for policy_key, p in app.policies : can(regex("^[a-z][a-z0-9_-]*$", policy_key)) && contains(["allow", "non_identity", "deny"], p.decision) && length(p.include) > 0 && p.precedence >= 1 && floor(p.precedence) == p.precedence])
    ])
    error_message = "Use stable logical keys and explicit existing policies."
  }
}
variable "routes" {
  type = map(object({
    hostname    = string
    service     = string
    application = optional(string)
    dns_comment = string
  }))
  validation {
    condition = length(var.routes) > 0 && alltrue([for key, route in var.routes :
      can(regex("^[a-z][a-z0-9_-]*$", key)) && startswith(route.service, "https://") &&
      !strcontains(route.hostname, "internal.") && !strcontains(route.hostname, "_acme-challenge") &&
      (route.application == null || contains(keys(var.applications), route.application))
    ])
    error_message = "Declare nonempty public HTTPS routes and exact Access bindings; exclude private and ACME DNS."
  }
}
