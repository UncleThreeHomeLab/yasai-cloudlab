"""Observe configured External Secrets delivery without refreshing credentials."""

import datetime as dt
import json
import re
import subprocess
import sys


TOKEN_REF = {"name": "onepassword-token", "namespace": "external-secrets", "key": "token"}
DNS_FIELD_TEMPLATE = (
    '{{- $value := index . "%s" -}}{{- if not $value -}}'
    '{{- fail "Required DNS credential field is missing or empty" -}}{{- end -}}{{ $value }}'
)
REFERENCE_DEFAULTS = {
    "conversionStrategy": "Default",
    "decodingStrategy": "None",
    "metadataPolicy": "None",
    "property": "",
    "version": "",
}
BACKUP_FIELDS = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_ENDPOINTS", "BUCKET", "REGION")
REFRESH_GRACE = dt.timedelta(minutes=15)


def get_resource(resource, name, namespace=None):
    args = ["/usr/local/bin/k3s", "kubectl", "--request-timeout=15s", "get", f"{resource}/{name}", "-o", "json"]
    if namespace:
        args.extend(["--namespace", namespace])
    result = subprocess.run(args, capture_output=True, check=True, timeout=20)
    document = json.loads(result.stdout)
    metadata = document["metadata"]
    if metadata.get("name") != name or metadata.get("namespace") != namespace or metadata.get("deletionTimestamp"):
        raise ValueError("Unexpected resource identity")
    return document


def ready_condition(document):
    conditions = [entry for entry in document["status"]["conditions"] if entry["type"] == "Ready"]
    if len(conditions) != 1 or conditions[0].get("status") != "True":
        raise ValueError("Resource is not ready")
    return conditions[0]


def refresh_interval(value):
    # ESO emits Go durations, for example 24h0m0s for the declared 24h.
    match = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+(?:\.\d+)?)s)?", value)
    if not match or not value:
        raise ValueError("Unsupported refresh interval")
    hours, minutes, seconds = (float(part or 0) for part in match.groups())
    return dt.timedelta(hours=hours, minutes=minutes, seconds=seconds)


def matches_reference(reference, key):
    return (
        reference.get("key") == key
        and reference.keys() <= REFERENCE_DEFAULTS.keys() | {"key"}
        and all(reference.get(field, default) == default for field, default in REFERENCE_DEFAULTS.items())
    )


def verify_external_secret(namespace, name, target, store, interval, source_bindings):
    document = get_resource("externalsecrets.external-secrets.io", name, namespace)
    spec = document["spec"]
    target_spec = spec["target"]
    actual_interval = refresh_interval(spec["refreshInterval"])
    if (
        spec["secretStoreRef"] != {"name": store, "kind": "ClusterSecretStore"}
        or spec.get("refreshPolicy", "Periodic") != "Periodic"
        or actual_interval <= dt.timedelta()
        or actual_interval != refresh_interval(interval)
        or target_spec.get("name") != target
        or target_spec.get("creationPolicy") != "Owner"
        or target_spec.get("deletionPolicy") != "Retain"
        or target_spec.get("immutable", False) is not False
        or target_spec.keys() - {"name", "creationPolicy", "deletionPolicy", "template", "immutable"}
    ):
        raise ValueError("Unexpected delivery configuration")

    if namespace == "cert-manager":
        sources = spec.get("dataFrom", [])
        if (
            len(sources) != 1
            or not matches_reference(sources[0].get("extract", {}), source_bindings)
            or any(sources[0].get(key) for key in ("sourceRef", "find", "rewrite"))
            or spec.get("data")
        ):
            raise ValueError("Unexpected certificate source binding")
        merge_policy = "Replace"
        template_data = {field: DNS_FIELD_TEMPLATE % field for field in ("API_TOKEN", "ZONE_ID")}
    else:
        sources = spec.get("data", [])
        if (
            len(sources) != len(source_bindings)
            or {entry["secretKey"] for entry in sources} != source_bindings.keys()
            or any(
                entry.get("sourceRef") or not matches_reference(entry["remoteRef"], source_bindings[entry["secretKey"]])
                for entry in sources
            )
            or spec.get("dataFrom")
        ):
            raise ValueError("Unexpected backup source binding")
        merge_policy = "Merge"
        template_data = {"VIRTUAL_HOSTED_STYLE": "false"}

    # Match the owning charts so a successful sync cannot attest a substituted output.
    template = target_spec["template"]
    if (
        template.get("engineVersion", "v2") != "v2"
        or template.get("mergePolicy", "Replace") != merge_policy
        or template.get("data") != template_data
        or template.get("metadata", {}) != {}
        or template.get("templateFrom", []) != []
        or template.get("type", "") != ""
        or template.keys() - {"engineVersion", "mergePolicy", "data", "metadata", "templateFrom", "type"}
    ):
        raise ValueError("Unexpected credential target template")

    status = document["status"]
    condition = ready_condition(document)
    generation = document["metadata"]["generation"]
    synced_revision = status["syncedResourceVersion"]
    prefix = f"{generation}-"
    if (
        condition.get("reason") != "SecretSynced"
        # ESO v2.11.0 also reports SecretSynced after retaining a missing source.
        or condition.get("message") != "secret synced"
        or status["binding"]["name"] != target
        or type(generation) is not int
        or generation < 1
        or not synced_revision.startswith(prefix)
        or len(synced_revision) == len(prefix)
    ):
        raise ValueError("Current generation has no successful target sync")

    refreshed = dt.datetime.fromisoformat(status["refreshTime"])
    if refreshed.utcoffset() != dt.timedelta():
        raise ValueError("Last successful sync has no UTC timestamp")
    age = dt.datetime.now(dt.timezone.utc) - refreshed
    if not dt.timedelta() <= age <= actual_interval + REFRESH_GRACE:
        raise ValueError("Last successful sync falls outside the refresh window")


def main(config):
    store = config["store"]
    document = get_resource("clustersecretstores.external-secrets.io", store)
    provider = document["spec"]["provider"]
    if provider != {"onepasswordSDK": {"vault": config["vault"], "auth": {"serviceAccountSecretRef": TOKEN_REF}}}:
        raise ValueError("Unexpected ClusterSecretStore provider")
    ready_condition(document)

    if config["certificates"]:
        verify_external_secret("cert-manager", "cloudlab-dns01", "cloudlab-dns01", store, "24h", "cloudlab-dns01")
    if config["backup"]:
        policy = config["backup_policy"]
        bindings = {field: f"{policy['item']}/{field}" for field in BACKUP_FIELDS}
        verify_external_secret(
            "longhorn-system", policy["external_secret_name"], policy["secret_name"],
            store, policy["refresh_interval"], bindings
        )

    anchors = int(config["certificates"]) + int(config["backup"])
    if anchors:
        print(f"CloudLab store ready; recent successful ESO sync observed for {anchors} production credentials.")
    else:
        print("CloudLab store ready; no production delivery anchors configured.")


if __name__ == "__main__":
    try:
        main(json.load(sys.stdin))
    except (AttributeError, KeyError, OSError, OverflowError, TypeError, ValueError, subprocess.SubprocessError):
        sys.exit("External Secrets readiness or delivery verification failed.")
