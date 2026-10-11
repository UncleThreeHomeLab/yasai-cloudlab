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
