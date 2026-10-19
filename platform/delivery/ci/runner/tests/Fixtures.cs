using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using GitHub.DistributedTask.Pipelines;
using GitHub.DistributedTask.Pipelines.ContextData;
using GitHub.Runner.Worker;

namespace GitHub.Runner.Common.Tests.Worker
{
    internal static class TrustedWorkflowFixtures
    {
        internal static Dictionary<string, string> Values(string job = "publish") => new()
        {
            ["repository_id"] = "42",
            ["repository"] = "example/private-app",
            ["workflow_ref"] = "example/private-app/.github/workflows/publish.yml@refs/heads/main",
            ["workflow_sha"] = new string('a', 40),
            ["sha"] = new string('a', 40),
            ["ref"] = "refs/heads/main",
            ["event_name"] = "workflow_dispatch",
            ["job"] = job
        };

        internal static byte[] Policy(Dictionary<string, string> row = null) =>
            JsonSerializer.SerializeToUtf8Bytes(new { workflows = new[] { row ?? Values() } });

        internal static void SetGithub(AgentJobRequestMessage message, Dictionary<string, string> row = null)
        {
            var github = new DictionaryContextData();
            foreach (var pair in row ?? Values(message.JobName))
                if (pair.Key != "job")
                    github[pair.Key] = new StringContextData(pair.Value);
            message.ContextData["github"] = github;
        }

        internal static AgentJobRequestMessage Message(string job = "publish",
            GitHub.DistributedTask.ObjectTemplating.Tokens.TemplateToken container = null,
            GitHub.DistributedTask.ObjectTemplating.Tokens.TemplateToken services = null,
            GitHub.DistributedTask.ObjectTemplating.Tokens.TemplateToken snapshot = null)
        {
            var message = new AgentJobRequestMessage(null, null, Guid.NewGuid(), job, job,
                container, services, null, new Dictionary<string, GitHub.DistributedTask.WebApi.VariableValue>(),
                new List<GitHub.DistributedTask.WebApi.MaskHint>(), new JobResources(),
                new DictionaryContextData(), new WorkspaceOptions(), new List<JobStep>(),
                null, null, null, null, snapshot);
            SetGithub(message);
            return message;
        }

        internal static void Install(string job)
        {
            if (File.Exists(TrustedWorkflow.PolicyPath))
                throw new InvalidOperationException("Refuse to overwrite an existing runner policy in the SDK fixture.");
            Directory.CreateDirectory(Path.GetDirectoryName(TrustedWorkflow.PolicyPath));
            using var file = new FileStream(TrustedWorkflow.PolicyPath, FileMode.CreateNew, FileAccess.Write);
            file.Write(Policy(Values(job)));
        }

        internal static void Remove() => File.Delete(TrustedWorkflow.PolicyPath);
    }
}
