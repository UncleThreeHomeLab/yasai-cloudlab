using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using GitHub.DistributedTask.Pipelines;

namespace GitHub.Runner.Worker
{
    internal static class TrustedTemplate
    {
        private static readonly string[] Fields = {
            "repository_id", "repository", "workflow_path", "workflow_sha256", "job", "visibility", "job_workflow_ref"
        };

        internal static bool Allows(AgentJobRequestMessage message, IReadOnlyDictionary<string, string> actual,
            JsonElement templates, Func<string, JsonDocument> fetch, Action<string> diagnostic)
        {
            try
            {
                diagnostic?.Invoke("workflow-identity");
                if (templates.ValueKind != JsonValueKind.Array || templates.GetArrayLength() is < 1 or > 16 ||
                    actual["sha"] != actual["workflow_sha"])
                    return false;
                JsonElement? match = null;
                var actualWorkflow = CalledWorkflow(message);
                var unique = new HashSet<string>(StringComparer.Ordinal);
                foreach (var row in templates.EnumerateArray())
                {
                    if (row.ValueKind != JsonValueKind.Object ||
                        row.EnumerateObject().Count() != Fields.Length ||
                        !row.EnumerateObject().Select(p => p.Name).ToHashSet().SetEquals(Fields) ||
                        Fields.Any(k => row.GetProperty(k).ValueKind != JsonValueKind.String))
                        return false;
                    string Value(string key) => row.GetProperty(key).GetString();
                    if (!Regex.IsMatch(Value("workflow_path"), @"\A\.github/workflows/[A-Za-z0-9_.-]+\.ya?ml\z") ||
                        !Regex.IsMatch(Value("workflow_sha256"), @"\A[a-f0-9]{64}\z") ||
                        Value("job") is not ("test" or "publish") ||
                        !Regex.IsMatch(Value("job_workflow_ref"), @"\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/\.github/workflows/application-(test|publish)\.yaml@[a-f0-9]{40}\z") ||
                        !Value("job_workflow_ref").Contains("/application-" + Value("job") + ".yaml@", StringComparison.Ordinal) ||
                        Value("visibility") is not ("public" or "private") ||
                        !unique.Add(string.Join("\0", Fields.Select(Value))))
                        return false;
                    if (Value("repository_id") == actual["repository_id"] && Value("repository") == actual["repository"] &&
                        Value("job_workflow_ref") == actualWorkflow &&
                        (actual["job"] == "__default" || Value("job") == actual["job"]) && actual["workflow_ref"] ==
                        Value("repository") + "/" + Value("workflow_path") + "@" + actual["ref"])
                    {
                        if (match.HasValue) return false;
                        match = row;
                    }
                }
                if (!match.HasValue) return false;
                var expected = match.Value;
                // GitHub uses __default for reusable jobs. Bind the role to its original immutable single-job workflow.
                var identity = actual.ToDictionary(pair => pair.Key, pair => pair.Value, StringComparer.Ordinal);
                identity["job"] = expected.GetProperty("job").GetString();
                if (!TrustedWorkflow.Valid(identity)) return false;
                diagnostic?.Invoke("job-token");
                using var client = fetch == null ? Client(message) : null;
                if (fetch == null && client == null) return false;
                fetch ??= path => Read(client, path, diagnostic);
                var prefix = "repos/" + actual["repository"];
                diagnostic?.Invoke("repository");
                using var repository = fetch(prefix);
                var repo = repository.RootElement;
                if (repo.GetProperty("id").GetInt64().ToString(System.Globalization.CultureInfo.InvariantCulture) != actual["repository_id"] ||
                    repo.GetProperty("full_name").GetString() != actual["repository"] ||
                    repo.GetProperty("private").GetBoolean() != (expected.GetProperty("visibility").GetString() == "private") ||
                    repo.GetProperty("fork").GetBoolean() || repo.GetProperty("archived").GetBoolean() ||
                    repo.GetProperty("disabled").GetBoolean() || repo.GetProperty("default_branch").GetString() != "main")
                    return false;
                diagnostic?.Invoke("main-policy");
                using var branch = fetch(prefix + "/branches/main");
                if (!branch.RootElement.GetProperty("protected").GetBoolean()) return false;
                if (actual["ref"] == "refs/heads/main")
                {
                    if (branch.RootElement.GetProperty("commit").GetProperty("sha").GetString() != actual["sha"])
                        return false;
                }
                else
                {
                    diagnostic?.Invoke("pull-request");
                    var number = Regex.Match(actual["ref"], @"\Arefs/pull/([1-9][0-9]*)/merge\z");
                    if (!number.Success || actual["event_name"] != "pull_request" || identity["job"] != "test") return false;
                    using var request = fetch(prefix + "/pulls/" + number.Groups[1].Value);
                    var pr = request.RootElement;
                    if (pr.GetProperty("state").GetString() != "open" ||
                        pr.GetProperty("mergeable").ValueKind != JsonValueKind.True ||
                        pr.GetProperty("merge_commit_sha").GetString() != actual["sha"] ||
                        pr.GetProperty("base").GetProperty("ref").GetString() != "main" ||
                        pr.GetProperty("author_association").GetString() is not ("OWNER" or "MEMBER" or "COLLABORATOR"))
                        return false;
                    foreach (var side in new[] { "head", "base" })
                    {
                        var origin = pr.GetProperty(side).GetProperty("repo");
                        if (origin.GetProperty("id").GetInt64().ToString(System.Globalization.CultureInfo.InvariantCulture) != actual["repository_id"] ||
                            origin.GetProperty("full_name").GetString() != actual["repository"] || origin.GetProperty("fork").GetBoolean())
                            return false;
                    }
                }
                diagnostic?.Invoke("workflow-content");
                var workflowPath = expected.GetProperty("workflow_path").GetString();
                using var workflow = fetch(prefix + "/contents/" + workflowPath + "?ref=" + actual["workflow_sha"]);
                var file = workflow.RootElement;
                if (file.GetProperty("type").GetString() != "file" || file.GetProperty("path").GetString() != workflowPath ||
                    file.GetProperty("encoding").GetString() != "base64" || file.GetProperty("size").GetInt32() is < 1 or > 65536)
                    return false;
                var content = Convert.FromBase64String(file.GetProperty("content").GetString());
                return content.Length == file.GetProperty("size").GetInt32() &&
                    Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant() == expected.GetProperty("workflow_sha256").GetString();
            }
            catch (Exception error) when (error is JsonException || error is InvalidOperationException ||
                error is KeyNotFoundException || error is FormatException || error is HttpRequestException ||
                error is IOException || error is OperationCanceledException || error is ArgumentException)
            {
                if (error is OperationCanceledException) diagnostic?.Invoke("github-timeout");
                return false;
            }
        }

        private static string CalledWorkflow(AgentJobRequestMessage message)
        {
            if (message.Variables == null ||
                !message.Variables.TryGetValue("system.workflowFileFullPath", out var path) ||
                !message.Variables.TryGetValue("system.workflowFileSha", out var revision) || path == null || revision == null)
                return null;
            return path.Value + "@" + revision.Value;
        }

        private static HttpClient Client(AgentJobRequestMessage message)
        {
            // Read the server's original job token before any step can change environment or context.
            if (message.Variables == null || !message.Variables.TryGetValue("system.github.token", out var value) ||
                string.IsNullOrWhiteSpace(value.Value) || value.Value.Any(char.IsWhiteSpace))
                return null;
            var client = new HttpClient(new HttpClientHandler { AllowAutoRedirect = false, UseProxy = false })
            { BaseAddress = new Uri("https://api.github.com/"), Timeout = TimeSpan.FromSeconds(5) };
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", value.Value);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("cloudlab-runner/1");
            client.DefaultRequestHeaders.Add("X-GitHub-Api-Version", "2022-11-28");
            client.DefaultRequestHeaders.Accept.ParseAdd("application/vnd.github+json");
            return client;
        }

        private static JsonDocument Read(HttpClient client, string path, Action<string> diagnostic)
        {
            using var cancellation = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            using var response = client.GetAsync(path, HttpCompletionOption.ResponseHeadersRead, cancellation.Token).GetAwaiter().GetResult();
            if (!response.IsSuccessStatusCode)
            {
                diagnostic?.Invoke("github-http-" + (int)response.StatusCode);
                throw new HttpRequestException("Eligibility API unavailable.");
            }
            using var input = response.Content.ReadAsStreamAsync(cancellation.Token).GetAwaiter().GetResult();
            using var output = new MemoryStream();
            var buffer = new byte[8192];
            int count;
            while ((count = input.ReadAsync(buffer.AsMemory(), cancellation.Token).GetAwaiter().GetResult()) > 0)
            {
                if (output.Length + count > 262144) throw new IOException("Eligibility response exceeds its bound.");
                output.Write(buffer, 0, count);
            }
            return JsonDocument.Parse(output.ToArray(), new JsonDocumentOptions { MaxDepth = 32 });
        }
    }
}
