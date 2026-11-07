locals {
  # Settings come only from the reviewed compiled binding; contract.json
  # records the accepted inputs for offline comparison, not provider inputs.
  projects    = toset(keys(var.registry.projects))
  groups      = toset([for member in values(var.registry.memberships) : member.group])
  memberships = var.registry.memberships
  robots = merge([for project in local.projects : {
    for role in ["push", "pull"] : "${project}-${role}" => { project = project, role = role }
  }]...)
}

resource "harbor_project" "project" {
  for_each                    = local.projects
  name                        = each.key
  public                      = false
  storage_quota               = var.registry.projects[each.key]
  vulnerability_scanning      = false
  enable_content_trust        = false
  enable_content_trust_cosign = false
  auto_sbom_generation        = false
  force_destroy               = false
  lifecycle { prevent_destroy = true }
}

resource "harbor_group" "group" {
  for_each   = local.groups
  group_name = each.key
  group_type = 3
  lifecycle { prevent_destroy = true }
}

resource "harbor_project_member_group" "member" {
  for_each   = local.memberships
  project_id = harbor_project.project[each.value.project].id
  group_id   = tonumber(trimprefix(harbor_group.group[each.value.group].id, "/usergroups/"))
  group_name = each.value.group
  type       = "oidc"
  role       = each.value.role
  lifecycle { prevent_destroy = true }
}

resource "harbor_robot_account" "robot" {
  for_each          = local.robots
  name              = each.value.role
  description       = "Scoped ${each.value.role} for ${each.value.project}"
  level             = "project"
  duration          = -1
  secret_wo         = var.robot_secrets[each.key]
  secret_wo_version = 1
  permissions {
    kind      = "project"
    namespace = harbor_project.project[each.value.project].name
    dynamic "access" {
      for_each = each.value.role == "push" ? toset(["pull", "push"]) : toset(["pull"])
      content {
        action   = access.value
        resource = "repository"
        effect   = "allow"
      }
    }
  }
  lifecycle { prevent_destroy = true }
}

# Quotas bound storage. No unattended deletion precedes artifact-preservation proof.
resource "harbor_retention_policy" "retention" {
  for_each = local.projects
  scope    = harbor_project.project[each.key].id
  rule {
    always_retain      = true
    repo_matching      = "**"
    tag_matching       = "**"
    untagged_artifacts = true
  }
  lifecycle { prevent_destroy = true }
}

resource "harbor_immutable_tag_rule" "release" {
  for_each      = local.projects
  project_id    = harbor_project.project[each.key].id
  repo_matching = "**"
  tag_matching  = var.registry.protected_tags
  disabled      = false
  lifecycle { prevent_destroy = true }
}
