using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using GitHub.DistributedTask.ObjectTemplating.Tokens;
using GitHub.DistributedTask.Pipelines.ContextData;
using GitHub.Runner.Worker;
using Xunit;

namespace GitHub.Runner.Common.Tests.Worker
{
    public sealed class TrustedWorkflowL0
    {
        private static (GitHub.DistributedTask.Pipelines.AgentJobRequestMessage Message, byte[] Policy,
            Dictionary<string, object> Responses, Dictionary<string, string> Values) TemplateFixture(bool pullRequest = false, bool owned = false)
        {
            var values = TrustedWorkflowFixtures.Values("test");
            values["event_name"] = pullRequest ? "pull_request" : "push";
            values["ref"] = pullRequest ? "refs/pull/42/merge" : "refs/heads/main";
            values["workflow_ref"] = values["repository"] + "/.github/workflows/ci.yaml@" + values["ref"];
            var message = TrustedWorkflowFixtures.Message("__default", displayName: "test / test");
            if (owned)
                message.Variables["system.github.job"] = new GitHub.DistributedTask.WebApi.VariableValue { Value = "test" };
            else
            {
                message.Variables["system.workflowFileFullPath"] = new GitHub.DistributedTask.WebApi.VariableValue {
                    Value = "example/platform/.github/workflows/application-test.yaml" };
                message.Variables["system.workflowFileSha"] = new GitHub.DistributedTask.WebApi.VariableValue { Value = new string('c', 40) };
            }
            TrustedWorkflowFixtures.SetGithub(message, values);
            var content = Encoding.UTF8.GetBytes("approved immutable reusable workflow wrapper\n");
            var policy = JsonSerializer.SerializeToUtf8Bytes(new { templates = new[] { new {
                repository_id = values["repository_id"], repository = values["repository"], job = "test", visibility = "private",
                workflow_path = ".github/workflows/ci.yaml",
                job_workflow_ref = owned ? values["repository"] + "/.github/workflows/ci.yaml@refs/heads/main" : "example/platform/.github/workflows/application-test.yaml@" + new string('c', 40),
                workflow_sha256 = Convert.ToHexString(SHA256.HashData(content)).ToLowerInvariant()
            } } });
            var repo = new Dictionary<string, object> {
                ["id"] = 42, ["full_name"] = values["repository"], ["private"] = true, ["fork"] = false,
                ["archived"] = false, ["disabled"] = false, ["default_branch"] = "main"
            };
            var responses = new Dictionary<string, object> {
                ["repos/" + values["repository"]] = repo,
                ["repos/" + values["repository"] + "/branches/main"] = new Dictionary<string, object> {
                    ["protected"] = true, ["commit"] = new { sha = values["sha"] }
                },
                ["repos/" + values["repository"] + "/pulls/42"] = new Dictionary<string, object> {
                    ["state"] = "open", ["mergeable"] = true, ["merge_commit_sha"] = values["sha"],
                    ["author_association"] = "CONTRIBUTOR", ["user"] = new { login = "author", id = 7 },
                    ["base"] = new { @ref = "main", repo }, ["head"] = new { repo }
                },
                ["repos/" + values["repository"] + "/collaborators/author/permission"] =
                    new { permission = "write", user = new { login = "author", id = 7 } },
                ["repos/" + values["repository"] + "/contents/.github/workflows/ci.yaml?ref=" + values["sha"]] =
                    new { type = "file", path = ".github/workflows/ci.yaml", encoding = "base64", size = content.Length,
                          content = Convert.ToBase64String(content) }
            };
            return (message, policy, responses, values);
        }

        [Fact]
        public void RepositoryOwnedJobsRequireOriginalWorkflowIdentityAndCurrentTrustedSource()
        {
            foreach (bool pr in new[] { false, true })
            {
                var fixture = TemplateFixture(pr, owned: true);
                JsonDocument Fetch(string path) => JsonDocument.Parse(JsonSerializer.Serialize(fixture.Responses[path]));
                Assert.True(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
                var publishPolicy = Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(fixture.Policy)
                    .Replace("\"job\":\"test\"", "\"job\":\"publish\""));
                fixture.Message.Variables["system.github.job"].Value = "publish";
                Assert.Equal(!pr, TrustedWorkflow.Allows(fixture.Message, publishPolicy, Fetch));
                fixture.Message.Variables["system.github.job"].Value = "test";
                foreach (var key in new[] { "system.workflowFileFullPath", "system.workflowFileSha" })
                {
                    fixture.Message.Variables[key] = new GitHub.DistributedTask.WebApi.VariableValue { Value = "foreign" };
                    Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
                    fixture.Message.Variables.Remove(key);
                }
                var prefix = "repos/" + fixture.Values["repository"];
                var branch = (Dictionary<string, object>)fixture.Responses[prefix + "/branches/main"];
                branch["protected"] = false;
                Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
                branch["protected"] = true;
                var file = prefix + "/contents/.github/workflows/ci.yaml?ref=" + fixture.Values["sha"];
                fixture.Responses[file] = new { type = "file", path = ".github/workflows/ci.yaml", encoding = "base64",
                    size = 7, content = Convert.ToBase64String(Encoding.UTF8.GetBytes("changed")) };
                Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            }
        }

        [Fact]
        public void RepositoryOwnedRoleRequiresOriginalServerJobAndCannotUseEnvironmentOrDisplayName()
        {
            var fixture = TemplateFixture(true, owned: true);
            JsonDocument Fetch(string path) => JsonDocument.Parse(JsonSerializer.Serialize(fixture.Responses[path]));
            Assert.True(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            fixture.Message.Variables.Remove("system.github.job");
            fixture.Message.Variables["GITHUB_JOB"] = new GitHub.DistributedTask.WebApi.VariableValue { Value = "test" };
            ((DictionaryContextData)fixture.Message.ContextData["github"])["job"] = new StringContextData("test");
            Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            foreach (var role in new[] { "publish", "__default", "test / test", "", "Test" })
            {
                fixture.Message.Variables["system.github.job"] = new GitHub.DistributedTask.WebApi.VariableValue { Value = role };
                Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            }
            fixture.Message.Variables["system.github.job"] = null;
            Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
        }

        [Fact]
        public void RepositoryOwnedOriginalWorkflowRefAndRevisionStillFailClosed()
        {
            foreach (var key in new[] { "workflow_ref", "workflow_sha", "sha", "repository_id" })
            {
                var fixture = TemplateFixture(true, owned: true);
                ((DictionaryContextData)fixture.Message.ContextData["github"])[key] = new StringContextData("foreign");
                Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy,
                    path => throw new Exception("Changed original identity must fail before API access")));
            }
        }

        [Fact]
        public void RepositoryOwnedPrStillRejectsForkAndUntrustedAuthor()
        {
            var fixture = TemplateFixture(true, owned: true);
            JsonDocument Fetch(string path) => JsonDocument.Parse(JsonSerializer.Serialize(fixture.Responses[path]));
            Assert.True(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            var request = (Dictionary<string, object>)fixture.Responses["repos/example/private-app/pulls/42"];
            var original = request["head"];
            request["head"] = new { repo = new { id = 43, full_name = "foreign/fork", fork = true } };
            Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            request["head"] = original;
            fixture.Responses["repos/example/private-app/collaborators/author/permission"] =
                new { permission = "read", user = new { login = "author", id = 7 } };
            Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
        }

        [Fact]
        public void ReusableRoleRequiresTheOriginalPinnedWorkflowIdentityBeforeApiAccess()
        {
            var fixture = TemplateFixture(true);
            foreach (var key in new[] { "system.workflowFileFullPath", "system.workflowFileSha" })
            {
                var original = fixture.Message.Variables[key];
                fixture.Message.Variables.Remove(key);
                Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy,
                    path => throw new Exception("Unbound reusable workflow must not reach the API")));
                fixture.Message.Variables[key] = new GitHub.DistributedTask.WebApi.VariableValue { Value = "unapproved" };
                Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy,
                    path => throw new Exception("Changed reusable workflow must not reach the API")));
                fixture.Message.Variables[key] = original;
            }
        }

        [Fact]
        public void ApprovedTemplateFollowsOnlyCurrentProtectedMainWithUnchangedWorkflow()
        {
            var fixture = TemplateFixture();
            JsonDocument Fetch(string path) => JsonDocument.Parse(JsonSerializer.Serialize(fixture.Responses[path]));
            Assert.True(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            var branch = (Dictionary<string, object>)fixture.Responses["repos/example/private-app/branches/main"];
            branch["protected"] = false;
            Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            branch["protected"] = true;
            branch["commit"] = new { sha = new string('b', 40) };
            Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            var old = "repos/example/private-app/contents/.github/workflows/ci.yaml?ref=" + fixture.Values["sha"];
            fixture.Values["sha"] = fixture.Values["workflow_sha"] = new string('b', 40);
            TrustedWorkflowFixtures.SetGithub(fixture.Message, fixture.Values);
            var path = "repos/example/private-app/contents/.github/workflows/ci.yaml?ref=" + fixture.Values["sha"];
            fixture.Responses[path] = fixture.Responses[old];
            Assert.True(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            fixture.Responses[path] = new { type = "file", path = ".github/workflows/ci.yaml", encoding = "base64",
                size = 7, content = Convert.ToBase64String(Encoding.UTF8.GetBytes("changed")) };
            Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
        }

        [Fact]
        public void TemplatePrAdmissionRejectsForksOutsidersClosedAndStaleMerges()
        {
            var fixture = TemplateFixture(true);
            JsonDocument Fetch(string path) => JsonDocument.Parse(JsonSerializer.Serialize(fixture.Responses[path]));
            Assert.True(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            var request = (Dictionary<string, object>)fixture.Responses["repos/example/private-app/pulls/42"];
            foreach (var pair in new Dictionary<string, object> {
                ["state"] = "closed", ["mergeable"] = false, ["merge_commit_sha"] = new string('b', 40),
                ["head"] = new { repo = new { id = 43, full_name = "foreign/fork", fork = true } }
            })
            {
                var original = request[pair.Key];
                request[pair.Key] = pair.Value;
                Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
                request[pair.Key] = original;
            }
            fixture.Values["job"] = "publish";
            var publish = TrustedWorkflowFixtures.Message("publish");
            TrustedWorkflowFixtures.SetGithub(publish, fixture.Values);
            Assert.False(TrustedWorkflow.Allows(publish, fixture.Policy, Fetch));
        }

        [Fact]
        public void TemplatePrRequiresCurrentWritePermissionAndExactAuthorIdentity()
        {
            var fixture = TemplateFixture(true);
            JsonDocument Fetch(string path) => JsonDocument.Parse(JsonSerializer.Serialize(fixture.Responses[path]));
            var request = (Dictionary<string, object>)fixture.Responses["repos/example/private-app/pulls/42"];
            foreach (var association in new[] { "MEMBER", "CONTRIBUTOR", "NONE", "COLLABORATOR" })
            {
                request["author_association"] = association;
                Assert.True(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            }
            var path = "repos/example/private-app/collaborators/author/permission";
            foreach (var permission in new[] { "read", "none", "triage", "maintain", "unknown" })
            {
                fixture.Responses[path] = new { permission, user = new { login = "author", id = 7 } };
                Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            }
            fixture.Responses[path] = new { permission = "admin", user = new { login = "AUTHOR", id = 7 } };
            Assert.True(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            foreach (var user in new[] { new { login = "other", id = 7 }, new { login = "author", id = 8 } })
            {
                fixture.Responses[path] = new { permission = "write", user };
                Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            }
        }

        [Fact]
        public void TemplatePrUnknownOrMalformedAuthorAndPermissionApiFailureFailClosed()
        {
            var fixture = TemplateFixture(true);
            var request = (Dictionary<string, object>)fixture.Responses["repos/example/private-app/pulls/42"];
            JsonDocument Fetch(string path)
            {
                if (path.Contains("/collaborators/", StringComparison.Ordinal))
                    throw new System.Net.Http.HttpRequestException("unavailable");
                return JsonDocument.Parse(JsonSerializer.Serialize(fixture.Responses[path]));
            }
            Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
            foreach (var user in new[] { new { login = "../foreign", id = 7 }, new { login = "author", id = 0 } })
            {
                request["user"] = user;
                Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy,
                    path => path.Contains("/collaborators/", StringComparison.Ordinal)
                        ? throw new Exception("Invalid author must not reach permission endpoint")
                        : JsonDocument.Parse(JsonSerializer.Serialize(fixture.Responses[path]))));
            }
            request.Remove("user");
            Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy, Fetch));
        }

        [Fact]
        public void TemplateApiFailureMissingOriginalTokenAndChangedIdentityFailClosed()
        {
            var fixture = TemplateFixture();
            Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy));
            Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy,
                path => throw new System.Net.Http.HttpRequestException("unavailable")));
            var repository = (Dictionary<string, object>)fixture.Responses["repos/example/private-app"];
            foreach (var pair in new Dictionary<string, object> {
                ["id"] = 43, ["private"] = false, ["fork"] = true, ["disabled"] = true, ["archived"] = true,
                ["full_name"] = "foreign/app", ["default_branch"] = "other"
            })
            {
                var original = repository[pair.Key];
                repository[pair.Key] = pair.Value;
                Assert.False(TrustedWorkflow.Allows(fixture.Message, fixture.Policy,
                    path => JsonDocument.Parse(JsonSerializer.Serialize(fixture.Responses[path]))));
                repository[pair.Key] = original;
            }
        }

        [Fact]
        public void AcceptsOnlyTheExplicitlyApprovedPullRequestMergeForTests()
        {
            var values = TrustedWorkflowFixtures.Values("test");
            values["event_name"] = "pull_request";
            values["ref"] = "refs/pull/123/merge";
            values["workflow_ref"] = values["repository"] + "/.github/workflows/ci.yaml@" + values["ref"];
            var message = TrustedWorkflowFixtures.Message("test");
            TrustedWorkflowFixtures.SetGithub(message, values);
            Assert.True(TrustedWorkflow.Allows(message, TrustedWorkflowFixtures.Policy(values)));
            var changed = TrustedWorkflowFixtures.Values("test");
            foreach (var pair in values) changed[pair.Key] = pair.Value;
            changed["sha"] = new string('b', 40);
            TrustedWorkflowFixtures.SetGithub(message, changed);
            Assert.False(TrustedWorkflow.Allows(message, TrustedWorkflowFixtures.Policy(values)));
            Assert.False(TrustedWorkflow.Allows(message, TrustedWorkflowFixtures.Policy(changed)));
        }

        [Fact]
        public void PullRequestPolicyCannotAuthorizePublishingOrOtherRefs()
        {
            foreach (var job in new[] { "publish", "propose", "test" })
            {
                var values = TrustedWorkflowFixtures.Values(job);
                values["event_name"] = "pull_request";
                values["ref"] = job == "test" ? "refs/pull/123/head" : "refs/pull/123/merge";
                values["workflow_ref"] = values["repository"] + "/.github/workflows/ci.yaml@" + values["ref"];
                var message = TrustedWorkflowFixtures.Message(job);
                TrustedWorkflowFixtures.SetGithub(message, values);
                Assert.False(TrustedWorkflow.Allows(message, TrustedWorkflowFixtures.Policy(values)));
            }
        }

        [Theory]
        [InlineData("push")]
        [InlineData("workflow_dispatch")]
        public void AcceptsOnlyTheCompleteOriginalMessage(string eventName)
        {
            var values = TrustedWorkflowFixtures.Values();
            values["event_name"] = eventName;
            var message = TrustedWorkflowFixtures.Message();
            TrustedWorkflowFixtures.SetGithub(message, values);
            Assert.True(TrustedWorkflow.Allows(message, TrustedWorkflowFixtures.Policy(values)));
        }

        [Fact]
        public void EveryMetadataMismatchAndMissingOrWrongTypeFailsClosed()
        {
            foreach (var field in TrustedWorkflowFixtures.Values().Keys)
            {
                var message = TrustedWorkflowFixtures.Message(field == "job" ? "wrong_job" : "publish");
                var github = (DictionaryContextData)message.ContextData["github"];
                if (field != "job")
                    github[field] = new StringContextData("wrong");
                Assert.False(TrustedWorkflow.Allows(message, TrustedWorkflowFixtures.Policy()));
                if (field == "job")
                    continue;
                var values = TrustedWorkflowFixtures.Values();
                values.Remove(field);
                TrustedWorkflowFixtures.SetGithub(message, values);
                Assert.False(TrustedWorkflow.Allows(message, TrustedWorkflowFixtures.Policy()));
                github = (DictionaryContextData)message.ContextData["github"];
                github[field] = new BooleanContextData(true);
                Assert.False(TrustedWorkflow.Allows(message, TrustedWorkflowFixtures.Policy()));
            }
        }

        [Fact]
        public void EnvironmentCannotRepairUntrustedMetadata()
        {
            var message = TrustedWorkflowFixtures.Message();
            var github = (DictionaryContextData)message.ContextData["github"];
            github["sha"] = new StringContextData(new string('b', 40));
            message.Variables["GITHUB_SHA"] = new GitHub.DistributedTask.WebApi.VariableValue(new string('a', 40));
            github["job"] = new StringContextData("publish");
            Assert.False(TrustedWorkflow.Allows(message, TrustedWorkflowFixtures.Policy()));
        }

        [Fact]
        public void ContainersServicesAndSnapshotsCannotBypassTheBuildProfile()
        {
            var token = new StringToken(null, null, null, "forbidden");
            foreach (var message in new[] {
                TrustedWorkflowFixtures.Message(container: token),
                TrustedWorkflowFixtures.Message(services: token),
                TrustedWorkflowFixtures.Message(snapshot: token) })
                Assert.False(TrustedWorkflow.Allows(message, TrustedWorkflowFixtures.Policy()));
        }

        [Fact]
        public void InvalidAmbiguousOrOversizedPoliciesFailClosed()
        {
            var valid = Encoding.UTF8.GetString(TrustedWorkflowFixtures.Policy());
            foreach (var policy in new[] { "", "null", "[]", "{}", "{\"workflows\":[]}",
                valid.Replace("\"workflows\":", "\"workflows\":[],\"workflows\":"),
                valid.Replace("\"repository_id\":", "\"repository_id\":\"42\",\"repository_id\":"),
                valid.Replace("\"workflows\":", "\"unknown\":true,\"workflows\":"),
                valid.Replace("\"repository_id\":\"42\"", "\"repository_id\":42"),
                new string(' ', 16385) })
                Assert.False(TrustedWorkflow.Allows(TrustedWorkflowFixtures.Message(), Encoding.UTF8.GetBytes(policy)));
            var row = TrustedWorkflowFixtures.Values();
            var duplicate = JsonSerializer.SerializeToUtf8Bytes(new { workflows = new[] { row, row } });
            Assert.False(TrustedWorkflow.Allows(TrustedWorkflowFixtures.Message(), duplicate));
            Assert.False(TrustedWorkflow.Allows(null, TrustedWorkflowFixtures.Policy()));
            Assert.False(TrustedWorkflow.Allows(TrustedWorkflowFixtures.Message(), null));
        }

        [Theory]
        [InlineData("event_name", "pull_request")]
        [InlineData("event_name", "pull_request_target")]
        [InlineData("ref", "refs/heads/untrusted")]
        [InlineData("sha", "main")]
        [InlineData("repository_id", "*")]
        [InlineData("workflow_ref", "*")]
        public void PolicyCannotBroadenTheQualifiedScope(string field, string value)
        {
            var row = TrustedWorkflowFixtures.Values();
            row[field] = value;
            var message = TrustedWorkflowFixtures.Message();
            TrustedWorkflowFixtures.SetGithub(message, row);
            Assert.False(TrustedWorkflow.Allows(message, TrustedWorkflowFixtures.Policy(row)));
        }
    }
}
