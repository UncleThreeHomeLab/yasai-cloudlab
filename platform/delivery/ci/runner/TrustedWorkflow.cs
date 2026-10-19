using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.RegularExpressions;
using GitHub.DistributedTask.ObjectTemplating.Tokens;
using GitHub.DistributedTask.Pipelines;
using GitHub.DistributedTask.Pipelines.ContextData;

namespace GitHub.Runner.Worker
{
    internal static class TrustedWorkflow
    {
        internal const string PolicyPath = "/etc/cloudlab-runner/eligibility.json";
        private const int MaximumBytes = 16384;
        private static readonly string[] Fields = {
            "repository_id", "repository", "workflow_ref", "workflow_sha", "sha", "ref", "event_name", "job"
        };

        internal static void Enforce(AgentJobRequestMessage message)
        {
            try
            {
                var file = new FileInfo(PolicyPath);
                if (file.Exists && file.Length <= MaximumBytes && Allows(message, File.ReadAllBytes(PolicyPath)))
                    return;
            }
            catch (Exception error) when (error is IOException || error is UnauthorizedAccessException)
            {
                // The job must not learn policy contents or filesystem diagnostics.
            }
            throw new InvalidOperationException("Job is not eligible for this runner.");
        }

        internal static bool Allows(AgentJobRequestMessage message, byte[] policy)
        {
            if (message == null || policy == null || policy.Length == 0 || policy.Length > MaximumBytes ||
                !Empty(message.JobContainer) || !Empty(message.JobServiceContainers) || !Empty(message.Snapshot) ||
                message.ContextData == null || !message.ContextData.TryGetValue("github", out var context) ||
                context is not DictionaryContextData github)
                return false;

            var actual = new Dictionary<string, string>(StringComparer.Ordinal);
            foreach (var field in Fields)
            {
                if (field == "job")
                    actual[field] = message.JobName;
                else if (github.TryGetValue(field, out var value) && value is StringContextData text)
                    actual[field] = text.Value;
                else
                    return false;
            }

            try
            {
                using var document = JsonDocument.Parse(policy, new JsonDocumentOptions { MaxDepth = 4 });
                var root = document.RootElement;
                if (!ExactFields(root, new[] { "workflows" }))
                    return false;
                var workflows = root.GetProperty("workflows");
                if (workflows.ValueKind != JsonValueKind.Array || workflows.GetArrayLength() is < 1 or > 16)
                    return false;

                bool matched = false;
                var unique = new HashSet<string>(StringComparer.Ordinal);
                foreach (var row in workflows.EnumerateArray())
                {
                    if (!ExactFields(row, Fields))
                        return false;
                    var expected = new Dictionary<string, string>(StringComparer.Ordinal);
                    foreach (var field in Fields)
                    {
                        var value = row.GetProperty(field);
                        if (value.ValueKind != JsonValueKind.String)
                            return false;
                        expected[field] = value.GetString();
                    }
                    if (!Valid(expected) || !unique.Add(string.Join("\0", Fields.Select(field => expected[field]))))
                        return false;
                    matched |= Fields.All(field => string.Equals(actual[field], expected[field], StringComparison.Ordinal));
                }
                return matched;
            }
            catch (Exception error) when (error is JsonException || error is InvalidOperationException || error is ArgumentException)
            {
                return false;
            }
        }

        private static bool Empty(TemplateToken token) => token == null || token is NullToken ||
            token is MappingToken mapping && mapping.Count == 0 ||
            token is SequenceToken sequence && sequence.Count == 0;

        private static bool ExactFields(JsonElement value, IEnumerable<string> expected)
        {
            if (value.ValueKind != JsonValueKind.Object)
                return false;
            var names = new HashSet<string>(StringComparer.Ordinal);
            foreach (var property in value.EnumerateObject())
                if (!names.Add(property.Name))
                    return false;
            return names.SetEquals(expected);
        }

        private static bool Valid(IReadOnlyDictionary<string, string> row)
        {
            return Matches(row["repository_id"], "[1-9][0-9]{0,19}") &&
                Matches(row["repository"], "[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+") &&
                Matches(row["workflow_sha"], "[a-f0-9]{40}") && Matches(row["sha"], "[a-f0-9]{40}") &&
                row["ref"] == "refs/heads/main" &&
                (row["event_name"] is "push" or "workflow_dispatch") &&
                Matches(row["job"], "[A-Za-z_][A-Za-z0-9_-]{0,63}") &&
                Matches(row["workflow_ref"], Regex.Escape(row["repository"]) +
                    "/\\.github/workflows/[A-Za-z0-9_.-]+\\.ya?ml@refs/heads/main");
        }

        private static bool Matches(string value, string pattern) => value != null && value.Length <= 256 &&
            Regex.IsMatch(value, "\\A(?:" + pattern + ")\\z", RegexOptions.CultureInvariant);
    }
}
