mock_provider "github" {}

run "synthetic_contract" {
  command = plan
  variables {
    owner        = jsondecode(file("fixtures.json")).owner
    repositories = jsondecode(file("fixtures.json")).repositories
    rulesets     = jsondecode(file("fixtures.json")).rulesets
  }
  assert {
    condition     = !github_repository.repository["fixture"].archived
    error_message = "Repository fixture must stay active."
  }
}

run "existing_empty_repository" {
  command = plan
  variables {
    owner        = jsondecode(file("fixtures.json")).owner
    repositories = { fixture = merge(jsondecode(file("fixtures.json")).repositories.fixture, { default_branch = null }) }
    rulesets     = {}
  }
  assert {
    condition     = length(github_branch_default.default) == 0
    error_message = "An empty existing repository must not create a branch or history."
  }
}
