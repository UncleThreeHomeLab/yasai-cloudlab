package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gateway "github.com/moby/buildkit/frontend/gateway/client"
	gatepb "github.com/moby/buildkit/frontend/gateway/pb"
	"github.com/moby/buildkit/solver/pb"
	digest "github.com/opencontainers/go-digest"
	fstypes "github.com/tonistiigi/fsutil/types"
)

const testImage = "registry.example.invalid/cloudlab-public/test-environment@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

type fakeReference struct{}

func (fakeReference) ToState() (llb.State, error)                                   { return llb.Scratch(), nil }
func (fakeReference) Evaluate(context.Context) error                                { return nil }
func (fakeReference) ReadFile(context.Context, gateway.ReadRequest) ([]byte, error) { return nil, nil }
func (fakeReference) StatFile(context.Context, gateway.StatRequest) (*fstypes.Stat, error) {
	return nil, nil
}
func (fakeReference) ReadDir(context.Context, gateway.ReadDirRequest) ([]*fstypes.Stat, error) {
	return nil, nil
}

type fakeProcess struct{ err error }

func (p fakeProcess) Wait() error                                 { return p.err }
func (fakeProcess) Resize(context.Context, gateway.WinSize) error { return nil }
func (fakeProcess) Signal(context.Context, syscall.Signal) error  { return nil }

type fakeContainer struct {
	start                               gateway.StartRequest
	starts, releases                    int
	startError, waitError, releaseError error
	releaseCancelled                    bool
}

func (c *fakeContainer) Start(_ context.Context, r gateway.StartRequest) (gateway.ContainerProcess, error) {
	c.start = r
	c.starts++
	return fakeProcess{c.waitError}, c.startError
}
func (c *fakeContainer) Release(ctx context.Context) error {
	c.releases++
	c.releaseCancelled = ctx.Err() != nil
	return c.releaseError
}
func (*fakeContainer) ReadFile(context.Context, gateway.ReadContainerRequest) ([]byte, error) {
	return nil, nil
}
func (*fakeContainer) StatFile(context.Context, gateway.StatContainerRequest) (*fstypes.Stat, error) {
	return nil, nil
}
func (*fakeContainer) ReadDir(context.Context, gateway.ReadDirContainerRequest) ([]*fstypes.Stat, error) {
	return nil, nil
}

type fakeGateway struct {
	container fakeContainer
	request   gateway.NewContainerRequest
	sources   []string
}

func (g *fakeGateway) Solve(_ context.Context, r gateway.SolveRequest) (*gateway.Result, error) {
	if r.Frontend != "" || len(r.FrontendOpt) != 0 || len(r.CacheImports) != 0 || !r.Evaluate {
		return nil, errors.New("test execution requested a frontend or cache")
	}
	for _, raw := range r.Definition.Def {
		var op pb.Op
		if op.UnmarshalVT(raw) != nil {
			return nil, errors.New("invalid source operation")
		}
		if op.GetExec() != nil || op.GetFile() != nil || op.GetBuild() != nil {
			return nil, errors.New("test execution constructed a build operation")
		}
		if source := op.GetSource(); source != nil {
			g.sources = append(g.sources, source.Identifier)
		}
	}
	result := gateway.NewResult()
	result.SetRef(fakeReference{})
	return result, nil
}
func (*fakeGateway) ResolveImageConfig(context.Context, string, sourceresolver.Opt) (string, digest.Digest, []byte, error) {
	return "", "", []byte(`{"config":{"Env":["PATH=/usr/bin:/bin","IMAGE_SETTING=approved"]}}`), nil
}
func (g *fakeGateway) NewContainer(_ context.Context, r gateway.NewContainerRequest) (gateway.Container, error) {
	g.request = r
	return &g.container, nil
}

func TestDirectExecutionIsFreshOfflineReadOnlyAndNeverBuilds(t *testing.T) {
	t.Setenv("GITHUB_TOKEN", "must-not-enter-sandbox")
	var g fakeGateway
	for range 2 {
		if err := executeTests(context.Background(), &g, testImage, []string{"sh", "tests.sh"}, io.Discard, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if g.container.starts != 2 || g.container.releases != 2 {
		t.Fatal("test process or cleanup was cached")
	}
	if g.request.NetMode != pb.NetMode_NONE || len(g.request.Mounts) != 2 ||
		g.request.Mounts[1].Dest != "/app" || !g.request.Mounts[1].Readonly {
		t.Fatal("unsafe sandbox mounts/network")
	}
	if g.container.start.SecurityMode != pb.SecurityMode_SANDBOX || g.container.start.User != "0:0" ||
		g.container.start.Cwd != "/app" || len(g.container.start.SecretEnv) != 0 {
		t.Fatal("unsafe execution profile")
	}
	if strings.Contains(strings.Join(g.container.start.Env, "\n"), "GITHUB_TOKEN") {
		t.Fatal("host credential inherited")
	}
	if len(g.sources) != 4 || g.sources[0] != "docker-image://"+testImage || g.sources[1] != "local://source" {
		t.Fatal(g.sources)
	}
}

func TestFailureAndCancellationCannotSkipCleanupOrPass(t *testing.T) {
	for _, stage := range []string{"start", "process", "cleanup", "cancel"} {
		t.Run(stage, func(t *testing.T) {
			var g fakeGateway
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch stage {
			case "start":
				g.container.startError = errors.New("untrusted private detail")
			case "process":
				g.container.waitError = &gatepb.ExitError{ExitCode: 17}
			case "cleanup":
				g.container.releaseError = errors.New("cleanup broke")
			case "cancel":
				cancel()
			}
			err := executeTests(ctx, &g, testImage, []string{"false"}, io.Discard, io.Discard)
			if err == nil || g.container.releases != 1 || g.container.releaseCancelled {
				t.Fatal("failure passed or cleanup inherited cancellation")
			}
			if strings.Contains(err.Error(), "untrusted private detail") {
				t.Fatal("private diagnostics escaped")
			}
		})
	}
}

func TestConfigurationAndCredentialBoundaries(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	for _, text := range []string{`{"image":"` + testImage + `"}`, `{"image":"unversioned:latest"}`, `{"image":"` + testImage + `","unknown":true}`} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := readConfiguration(path)
		if (err == nil) != (text == `{"image":"`+testImage+`"}`) {
			t.Fatal(text, err)
		}
	}
	for _, value := range []string{
		`{"auths":{"registry.example.invalid":{"auth":"dXNlcjpwYXNzd29yZA=="}}}`,
		`{"auths":{"other.example.invalid":{"auth":"dXNlcjpwYXNzd29yZA=="}}}`,
		`{"auths":{"registry.example.invalid":{"auth":"dXNlcjpwYXNzd29yZA=="}},"credsStore":"unexpected"}`,
	} {
		if err := os.WriteFile(path, []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := registryAuthentication(path, testImage)
		if (err == nil) != (value == `{"auths":{"registry.example.invalid":{"auth":"dXNlcjpwYXNzd29yZA=="}}}`) {
			t.Fatal("credential boundary", err)
		}
	}
}

func git(t *testing.T, dir string, args ...string) {
	t.Helper()
	c := exec.Command("/usr/bin/git", args...)
	c.Dir = dir
	if raw, err := c.CombinedOutput(); err != nil {
		t.Fatal(err, string(raw))
	}
}

func TestSnapshotCopiesCurrentTrackedSourceWithoutState(t *testing.T) {
	dir := t.TempDir()
	git(t, dir, "init", "-q")
	if err := os.WriteFile(filepath.Join(dir, "source.py"), []byte("committed"), 0600); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "source.py")
	if err := os.WriteFile(filepath.Join(dir, "source.py"), []byte("current checkout"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".env", "ignored-secret"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("must not copy"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	snapshot, err := sourceSnapshot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(snapshot)
	files, err := os.ReadDir(snapshot)
	if err != nil || len(files) != 1 || files[0].Name() != "source.py" {
		t.Fatal(files, err)
	}
	raw, err := os.ReadFile(filepath.Join(snapshot, "source.py"))
	if err != nil || !bytes.Equal(raw, []byte("current checkout")) {
		t.Fatal("stale source", err)
	}
	git(t, dir, "add", "-f", ".env")
	if _, err := sourceSnapshot(dir); err == nil {
		t.Fatal("tracked credential path accepted")
	}
	git(t, dir, "rm", "--cached", ".env")
	if err := os.Symlink("/etc/passwd", filepath.Join(dir, "escape")); err != nil {
		t.Fatal(err)
	}
	git(t, dir, "add", "escape")
	if _, err := sourceSnapshot(dir); err == nil {
		t.Fatal("escaping symlink accepted")
	}
}

func TestSafeSourcePathsRejectTraversalAndPrivateState(t *testing.T) {
	for _, name := range []string{"../secret", "/secret", "a/../secret", "a\\secret", ".git/config", "credentials/a", "storage/a", ".env.production"} {
		if safeSourcePath(name) {
			t.Fatal(name)
		}
	}
	for _, name := range []string{"src/storage/api.py", "tests/test_api.py", ".env.example"} {
		if !safeSourcePath(name) {
			t.Fatal(name)
		}
	}
	var cfg configuration
	if json.Unmarshal([]byte(`{"image":"`+testImage+`"}`), &cfg) != nil || cfg.Image != testImage {
		t.Fatal("configuration contract")
	}
}
