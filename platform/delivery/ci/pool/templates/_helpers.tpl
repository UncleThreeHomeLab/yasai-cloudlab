{{- define "cloudlab.ci.pool.normalize" -}}
{{- if not (hasKey . "poolEnabled") }}
{{- $v := deepCopy .Values }}
{{- $registration := hasKey $v "registration" }}
{{- $component := hasKey $v "component" }}
{{- if ne $registration $component }}{{ fail "Pool registration and component belong together" }}{{- end }}
{{- if not $registration }}
{{- if and (hasKey $v.arc "enabled") (not $v.arc.enabled) }}{{ fail "Legacy pools cannot disable the scale set" }}{{- end }}
{{- $_ := set . "poolEnabled" true }}
{{- else }}
{{- if or (not (hasKey $v.arc "enabled")) (not (kindIs "bool" $v.arc.enabled)) }}{{ fail "Derived pools require the computed pool flag" }}{{- end }}
{{- $_ := set . "poolEnabled" $v.arc.enabled }}
{{- if $v.arc.enabled }}
{{- $r := $v.registration }}
{{- $app := $r.application }}
{{- $source := $r.source }}
{{- $vis := $source.visibility }}
{{- if ne .Release.Namespace (printf "cloudlab-ci-%s-%s" $vis $app) }}{{ fail "Derived pools require their visibility application namespace" }}{{- end }}
{{- $ci := $r.ci }}
{{- if ne $ci.profile (printf "%s-main" $vis) }}{{ fail "Pool profile must match its source visibility" }}{{- end }}
{{- $approval := $ci.approval }}
{{- $jobs := $ci.jobs }}
{{- if not (kindIs "bool" $jobs.test) }}{{ fail "Derived pools require the test job decision" }}{{- end }}
{{- $publish := false }}
{{- if hasKey $jobs "publish" }}{{ $publish = $jobs.publish }}{{- end }}
{{- if not (kindIs "bool" $publish) }}{{ fail "Derived pools require the publishing job decision" }}{{- end }}
{{- $pr := 0 }}
{{- if hasKey $approval "pullRequest" }}{{ $pr = int $approval.pullRequest }}{{- end }}
{{- if $pr }}
{{- if or (ne $vis "public") $publish }}{{ fail "Pull request approvals allow public test-only eligibility" }}{{- end }}
{{- end }}
{{- $comp := $v.component }}
{{- $scaleSet := printf "cloudlab-%s" $app }}
{{- $policy := "cloudlab-ci-eligibility" }}
{{- $shared := true }}
{{- if eq $comp "publisher" }}
{{- $scaleSet = printf "cloudlab-%s-publish" $app }}
{{- $policy = "cloudlab-ci-eligibility-publish" }}
{{- $shared = false }}
{{- if not $publish }}{{ fail "Publisher pools require the publishing job" }}{{- end }}
{{- if not (hasKey $r "publishing") }}{{ fail "Publisher pools require the publishing destination" }}{{- end }}
{{- if $pr }}{{ fail "Publisher pools require main approval" }}{{- end }}
{{- else }}
{{- if not (or $jobs.test $publish) }}{{ fail "Runner pools require the test or publishing job" }}{{- end }}
{{- end }}
{{- if ne .Values.arc.githubConfigUrl (printf "https://github.com/%s" $source.repository) }}{{ fail "Derived runner endpoint must match the approved repository" }}{{- end }}
{{- if ne .Values.arc.githubConfigSecret (ternary "github-arc-public" "github-arc" (eq $vis "public")) }}{{ fail "Derived runner credentials must match the pool visibility" }}{{- end }}
{{- if ne .Values.arc.runnerScaleSetName $scaleSet }}{{ fail "Derived scale set name must match the approved application" }}{{- end }}
{{- if not (kindIs "map" ($v.images | default dict)) }}{{ fail "Derived pools require platform images" }}{{- end }}
{{- $images := $v.images }}
{{- if not (and (hasKey $images "runner") (kindIs "string" $images.runner) (regexMatch "^[a-z0-9.-]+/cloudlab-public/ci-runner@sha256:[a-f0-9]{64}$" $images.runner)) }}{{ fail "Derived pools require the qualified runner image" }}{{- end }}
{{- if not (and (hasKey $images "builder") (kindIs "string" $images.builder) (regexMatch "^[a-z0-9.-]+/cloudlab-public/ci-builder@sha256:[a-f0-9]{64}$" $images.builder)) }}{{ fail "Derived pools require the qualified builder image" }}{{- end }}
{{- $runnerContainer := index .Values.arc.template.spec.containers 0 }}
{{- $builderContainer := index .Values.arc.template.spec.initContainers 0 }}
{{- if ne $runnerContainer.image $images.runner }}{{ fail "Derived pools require the qualified runner image" }}{{- end }}
{{- if ne $builderContainer.image $images.builder }}{{ fail "Derived pools require the qualified builder image" }}{{- end }}
{{- $ref := "refs/heads/main" }}
{{- if $pr }}{{ $ref = printf "refs/pull/%d/merge" $pr }}{{- end }}
{{- $workflowRef := printf "%s/.github/workflows/ci.yaml@%s" $source.repository $ref }}
{{- $entries := list }}
{{- if $pr }}
{{- $entries = append $entries (dict "repository_id" $source.repositoryId "repository" $source.repository "workflow_ref" $workflowRef "workflow_sha" $approval.revision "sha" $approval.revision "ref" $ref "event_name" "pull_request" "job" "test") }}
{{- else if eq $comp "publisher" }}
{{- range $event := list "push" "workflow_dispatch" }}
{{- $entries = append $entries (dict "repository_id" $source.repositoryId "repository" $source.repository "workflow_ref" $workflowRef "workflow_sha" $approval.revision "sha" $approval.revision "ref" $ref "event_name" $event "job" "publish") }}
{{- end }}
{{- else }}
{{- $runnerJobs := list }}
{{- if $jobs.test }}{{ $runnerJobs = append $runnerJobs "test" }}{{- end }}
{{- if $publish }}{{ $runnerJobs = append $runnerJobs "build" }}{{- end }}
{{- range $job := $runnerJobs }}
{{- range $event := list "push" "workflow_dispatch" }}
{{- $entries = append $entries (dict "repository_id" $source.repositoryId "repository" $source.repository "workflow_ref" $workflowRef "workflow_sha" $approval.revision "sha" $approval.revision "ref" $ref "event_name" $event "job" $job) }}
{{- end }}
{{- end }}
{{- end }}
{{- $_ := set .Values "eligibility" $entries }}
{{- $_ := set .Values "policyName" $policy }}
{{- $_ := set .Values "manageSharedResources" $shared }}
{{- if hasKey .Values "workflowTemplates" }}{{ $_ := unset .Values "workflowTemplates" }}{{- end }}
{{- if and (eq $comp "runner") (hasKey $r "testing") }}
{{- $image := $r.testing.image }}
{{- $private := eq $vis "private" }}
{{- $project := ternary "cloudlab-private" "cloudlab-public" $private }}
{{- if not (regexMatch (printf "^[^/]+/%s/" $project) $image) }}{{ fail "Test environment must match the pool visibility" }}{{- end }}
{{- $_ := set .Values "testing" (dict "image" $image) }}
{{- else }}
{{- if hasKey .Values "testing" }}{{ $_ := unset .Values "testing" }}{{- end }}
{{- end }}
{{- if eq $comp "publisher" }}
{{- $p := $r.publishing }}
{{- $releaseVis := $p.releaseVisibility | default $vis }}
{{- $releaseMode := $p.releaseMode | default "automatic" }}
{{- if and (eq $releaseMode "manual") (ne $releaseVis "private") }}{{ fail "Manual promotion releases to private GitOps only" }}{{- end }}
{{- if and (eq $vis "private") (ne $releaseVis "private") }}{{ fail "Private sources release to private GitOps only" }}{{- end }}
{{- $out := dict "application" $app "source_repository" $source.repository "source_repository_id" $source.repositoryId "visibility" $vis "registry" $p.registry "project" (printf "cloudlab-%s" $vis) "release_repository" $p.releaseRepository "release_repository_id" (int $p.releaseRepositoryId) "workflow_identity" $p.workflowIdentity "release_visibility" $releaseVis "release_mode" $releaseMode }}
{{- if hasKey $p "components" }}
{{- if not (hasKey $p "primaryComponent") }}{{ fail "Publishing requires an explicit component primary" }}{{- end }}
{{- $_ := set $out "components" $p.components }}
{{- $_ := set $out "primary_component" $p.primaryComponent }}
{{- else if hasKey $p "primaryComponent" }}
{{- fail "Publishing requires an explicit component primary" }}
{{- end }}
{{- $_ := set .Values "publishing" $out }}
{{- else }}
{{- if hasKey .Values "publishing" }}{{ $_ := unset .Values "publishing" }}{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
{{- end }}
