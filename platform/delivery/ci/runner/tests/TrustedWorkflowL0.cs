using System;
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
