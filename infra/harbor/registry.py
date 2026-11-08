"""Compile supported registry YAML into provider inputs with plan guards.

A binding declares only existing projects and approved membership profiles. It
authorizes no new project, credential, import, garbage collection, or deletion.
Robot accounts stay vault/manual-owned outside binding scope; a binding that
declares `robots` is rejected as unsupported. A binding names both existing
projects; anything less is invalid input and never deletion intent. The
agreed trusted executor (`reconcile.py`, Compose service `infra-harbor`)
consumes `compile` output; this module validates bindings and reports diffs.
"""

import json
import sys
from pathlib import Path

import jsonschema
import yaml

HERE = Path(__file__).parent
SCHEMA = json.loads((HERE / "registry.schema.json").read_text())
CONTRACT = json.loads((HERE / "contract.json").read_text())

PROTECTED_TAGS = ["release-*", "deploy-*", "rollback-*"]
ROLE_SHORT = {"projectadmin": "admin", "developer": "developer", "guest": "viewer"}


def binding(path):
    try:
        value = yaml.safe_load(Path(path).read_text())
    except yaml.YAMLError as error:
        raise SystemExit("Invalid registry YAML: " + str(error)) from None
    try:
        jsonschema.validate(value, SCHEMA)
    except jsonschema.ValidationError as error:
        raise SystemExit("Unsupported registry binding: " + error.message) from None
    return value


def guards(value):
    if sorted(project["name"] for project in value["projects"]) != [
            "cloudlab-private", "cloudlab-public"]:
        raise SystemExit("A binding must name both existing registry projects")
    seen = set()
    for project in value["projects"]:
        name = project["name"]
        if name in seen:
            raise SystemExit("Duplicate project binding: " + name)
        seen.add(name)
        if sorted(project["immutableTags"]) != sorted(PROTECTED_TAGS):
            raise SystemExit("Immutable tags must keep exactly " + ",".join(PROTECTED_TAGS))
        roles = [member["role"] for member in project["members"]]
        if len(set(roles)) != len(roles):
            raise SystemExit("One group per role in project " + name)
        if {"group": "/platform-admin", "role": "projectadmin"} not in project["members"]:
            raise SystemExit("Project " + name + " must keep its platform administrator")
    return value


def compile_binding(value):
    memberships = {}
    for project in guards(value)["projects"]:
        visibility = project["name"].split("-", 1)[1]
        for member in sorted(project["members"], key=lambda row: row["role"]):
            key = visibility + "_" + ROLE_SHORT[member["role"]]
            memberships[key] = {"project": project["name"], "group": member["group"],
                                "role": member["role"]}
    return {"projects": {project["name"]: project["quotaGiB"] for project in value["projects"]},
            "memberships": memberships,
            "protected_tags": "{" + ",".join(PROTECTED_TAGS) + "}",
            "retention": "retain-all"}


def compile_command(path):
    print(json.dumps(compile_binding(binding(path)), indent=2, sort_keys=True))


def diff_command(path):
    compiled = compile_binding(binding(path))
    changes = []
    for name, quota in sorted(compiled["projects"].items()):
        current = CONTRACT["projects"].get(name)
        if current != quota:
            changes.append("project %s quota: %s -> %s" % (name, current, quota))
    current_members = {key: (row["group"], row["role"])
                       for key, row in CONTRACT["memberships"].items()}
    declared_projects = set(compiled["projects"])
    for key, row in sorted(compiled["memberships"].items()):
        if current_members.get(key) != (row["group"], row["role"]):
            changes.append("membership %s: %s -> %s/%s"
                           % (key, current_members.get(key), row["group"], row["role"]))
    for key, row in sorted(CONTRACT["memberships"].items()):
        if row["project"] in declared_projects and key not in compiled["memberships"]:
            changes.append("membership %s removed" % key)
    if compiled["protected_tags"] != CONTRACT["protected_tags"]:
        changes.append("protected tags: %s -> %s"
                       % (CONTRACT["protected_tags"], compiled["protected_tags"]))
    retained = sorted(set(CONTRACT["projects"]) - set(compiled["projects"]))
    for name in retained:
        print("retained: project %s is not declared; preserved, never deleted" % name)
    if changes:
        print("\n".join("change: " + line for line in changes))
        raise SystemExit(2)
    print("unchanged: binding matches accepted provider inputs")


def main(arguments):
    if len(arguments) != 2 or arguments[0] not in ("compile", "diff"):
        raise SystemExit("Usage: registry.py compile|diff BINDING.yaml")
    {"compile": compile_command, "diff": diff_command}[arguments[0]](arguments[1])


if __name__ == "__main__":
    main(sys.argv[1:])
