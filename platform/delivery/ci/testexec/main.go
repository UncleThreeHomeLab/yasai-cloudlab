package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/docker/cli/cli/config/types"
	buildkit "github.com/moby/buildkit/client"
	"github.com/moby/buildkit/client/llb"
	"github.com/moby/buildkit/client/llb/sourceresolver"
	gateway "github.com/moby/buildkit/frontend/gateway/client"
	gatepb "github.com/moby/buildkit/frontend/gateway/pb"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/moby/buildkit/solver/pb"
	digest "github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/tonistiigi/fsutil"
)

const endpoint = "tcp://127.0.0.1:1234"

var sourceSHA256 = "unversioned"

var immutableImage = regexp.MustCompile(`\A[a-z0-9][a-z0-9.-]*(?::[0-9]{1,5})?/[a-z0-9][a-z0-9._/-]*@sha256:[a-f0-9]{64}\z`)

type configuration struct {
	Image string `json:"image"`
}

func readConfiguration(path string) (configuration, error) {
	var cfg configuration
	f, err := os.Open(path)
	if err != nil {
		return cfg, errors.New("test environment configuration unavailable")
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || info.Size() > 16384 {
		return cfg, errors.New("invalid immutable test environment")
	}
	decoder := json.NewDecoder(io.LimitReader(f, 16385))
	opening, err := decoder.Token()
	key, keyErr := decoder.Token()
	if err != nil || keyErr != nil || opening != json.Delim('{') || key != "image" ||
		decoder.Decode(&cfg.Image) != nil || decoder.More() {
		return cfg, errors.New("invalid immutable test environment")
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') || decoder.Decode(new(any)) != io.EOF || !immutableImage.MatchString(cfg.Image) {
		return cfg, errors.New("invalid immutable test environment")
	}
	for _, part := range strings.Split(strings.Split(cfg.Image, "@")[0], "/") {
		if part == "" || part == "." || part == ".." {
			return cfg, errors.New("invalid immutable test environment")
		}
	}
	return cfg, nil
}

func registryAuthentication(path, image string) (session.Attachable, error) {
	host, repository, _ := strings.Cut(strings.Split(image, "@")[0], "/")
	credentials := types.AuthConfig{}
	raw, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, errors.New("test environment pull credential unavailable")
	}
	if err == nil {
		var cfg struct {
			Auths map[string]types.AuthConfig `json:"auths"`
		}
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if len(raw) > 65536 || decoder.Decode(&cfg) != nil || decoder.Decode(new(any)) != io.EOF || len(cfg.Auths) != 1 {
			return nil, errors.New("invalid test environment pull credential")
		}
		var found bool
		credentials, found = cfg.Auths[host]
		if !found || credentials.IdentityToken != "" || credentials.RegistryToken != "" {
			return nil, errors.New("test environment pull credential host differs")
		}
		if credentials.Auth != "" {
			decoded, err := base64.StdEncoding.DecodeString(credentials.Auth)
			if err != nil {
				return nil, errors.New("invalid test environment pull credential")
			}
			user, password, ok := strings.Cut(string(decoded), ":")
			if !ok || (credentials.Username != "" && credentials.Username != user) ||
				(credentials.Password != "" && credentials.Password != password) {
				return nil, errors.New("ambiguous test environment pull credential")
			}
			credentials.Username, credentials.Password = user, password
		}
		if credentials.Username == "" || credentials.Password == "" ||
			strings.ContainsAny(credentials.Username+credentials.Password, "\r\n\x00") {
			return nil, errors.New("invalid test environment pull credential")
		}
	}
	return authprovider.NewDockerAuthProvider(authprovider.DockerAuthProviderConfig{
		AuthConfigProvider: func(_ context.Context, requestedHost string, scopes []string, _ authprovider.ExpireCachedAuthCheck) (types.AuthConfig, error) {
			if requestedHost != host {
				return types.AuthConfig{}, nil
			}
			for _, scope := range scopes {
				if scope != "repository:"+repository+":pull" {
					return types.AuthConfig{}, errors.New("test environment credential is pull-only")
				}
			}
			return types.AuthConfig{Username: credentials.Username, Password: credentials.Password, ServerAddress: host}, nil
		},
	}), nil
}

func sourceSnapshot(source string) (snapshot string, err error) {
	root, err := filepath.Abs(source)
	if err != nil {
		return "", errors.New("test source unavailable")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return "", errors.New("test source unavailable")
	}
	command := gitCommand(root, "rev-parse", "--show-toplevel")
	declared, err := command.Output()
	if err != nil || filepath.Clean(strings.TrimSpace(string(declared))) != root {
		return "", errors.New("test source must be a Git checkout root")
	}
	command = gitCommand(root, "ls-files", "--stage", "-z")
	files, err := command.Output()
	if err != nil || len(files) == 0 || len(files) > 16*1024*1024 {
		return "", errors.New("test source index unavailable or oversized")
	}
	confined, err := os.OpenRoot(root)
	if err != nil {
		return "", errors.New("test source unavailable")
	}
	defer confined.Close()
	snapshot, err = os.MkdirTemp("/tmp", "cloudlab-test-source-")
	if err != nil {
		return "", errors.New("test source snapshot unavailable")
	}
	defer func() {
		if err != nil {
			os.RemoveAll(snapshot)
		}
	}()
	if err = os.Chmod(snapshot, 0755); err != nil {
		return snapshot, err
	}
	var total int64
	for _, entry := range strings.Split(strings.TrimSuffix(string(files), "\x00"), "\x00") {
		header, name, ok := strings.Cut(entry, "\t")
		parts := strings.Fields(header)
		if !ok || len(parts) != 3 || parts[2] != "0" || !safeSourcePath(name) ||
			(parts[0] != "100644" && parts[0] != "100755" && parts[0] != "120000") {
			return snapshot, errors.New("test source contains unsupported index entries")
		}
		destination := filepath.Join(snapshot, filepath.FromSlash(name))
		if err = os.MkdirAll(filepath.Dir(destination), 0755); err != nil {
			return snapshot, errors.New("test source snapshot unavailable")
		}
		info, statErr := confined.Lstat(name)
		if statErr != nil {
			return snapshot, errors.New("tracked test source unavailable")
		}
		if parts[0] == "120000" {
			link, readErr := confined.Readlink(name)
			if readErr != nil || filepath.IsAbs(link) {
				return snapshot, errors.New("test source link is not confined")
			}
			target := filepath.Clean(filepath.Join(filepath.Dir(name), link))
			if target == ".." || strings.HasPrefix(target, ".."+string(filepath.Separator)) {
				return snapshot, errors.New("test source link is not confined")
			}
			if err = os.Symlink(link, destination); err != nil {
				return snapshot, errors.New("test source snapshot unavailable")
			}
			continue
		}
		if !info.Mode().IsRegular() || info.Size() > 128*1024*1024 || total+info.Size() > 512*1024*1024 {
			return snapshot, errors.New("test source file is unsupported or oversized")
		}
		input, openErr := confined.OpenFile(name, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
		if openErr != nil {
			return snapshot, errors.New("test source file is not confined")
		}
		mode := os.FileMode(0644)
		if parts[0] == "100755" {
			mode = 0755
		}
		output, createErr := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if createErr != nil {
			input.Close()
			return snapshot, errors.New("test source snapshot unavailable")
		}
		written, copyErr := io.Copy(output, io.LimitReader(input, 128*1024*1024+1))
		closeErr := output.Close()
		input.Close()
		total += written
		if copyErr != nil || closeErr != nil || written != info.Size() {
			return snapshot, errors.New("test source changed during snapshot")
		}
	}
	return snapshot, nil
}

func gitCommand(root string, args ...string) *exec.Cmd {
	command := exec.Command("/usr/bin/git", append([]string{"-c", "safe.directory=" + root,
		"-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null"}, args...)...)
	command.Dir = root
	command.Env = []string{"PATH=/usr/bin:/bin", "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "GIT_OPTIONAL_LOCKS=0"}
	return command
}

func safeSourcePath(name string) bool {
	if name == "" || strings.ContainsAny(name, "\\\r\n\x00") || filepath.IsAbs(name) {
		return false
	}
	parts := strings.Split(name, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || part == ".git" {
			return false
		}
	}
	first := parts[0]
	return first != ".env" && !(strings.HasPrefix(first, ".env.") && first != ".env.example") &&
		first != "credentials" && first != "storage" && first != ".kube" && first != ".infra-private"
}

type executor interface {
	Solve(context.Context, gateway.SolveRequest) (*gateway.Result, error)
	ResolveImageConfig(context.Context, string, sourceresolver.Opt) (string, digest.Digest, []byte, error)
	NewContainer(context.Context, gateway.NewContainerRequest) (gateway.Container, error)
}

func executeTests(ctx context.Context, client executor, image string, command []string, stdout, stderr io.Writer) (err error) {
	resolve := func(state llb.State) (gateway.Reference, error) {
		definition, err := state.Marshal(ctx)
		if err != nil {
			return nil, err
		}
		result, err := client.Solve(ctx, gateway.SolveRequest{Definition: definition.ToPB(), Evaluate: true})
		if err != nil {
			return nil, err
		}
		return result.SingleRef()
	}
	root, err := resolve(llb.Image(image, llb.Platform(ocispec.Platform{OS: "linux", Architecture: "amd64"})))
	if err != nil {
		return errors.New("test environment could not be loaded")
	}
	source, err := resolve(llb.Local("source"))
	if err != nil {
		return errors.New("test source could not be loaded")
	}
	_, _, raw, err := client.ResolveImageConfig(ctx, image, sourceresolver.Opt{})
	var metadata ocispec.Image
	if err != nil || len(raw) > 65536 || json.Unmarshal(raw, &metadata) != nil {
		return errors.New("test environment configuration could not be loaded")
	}
	container, err := client.NewContainer(ctx, gateway.NewContainerRequest{
		NetMode:  pb.NetMode_NONE,
		Platform: &pb.Platform{OS: "linux", Architecture: "amd64"},
		Mounts:   []gateway.Mount{{Dest: "/", Ref: root}, {Dest: "/app", Ref: source, Readonly: true}},
	})
	if err != nil {
		return errors.New("offline test sandbox could not be created")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if container.Release(cleanup) != nil {
			err = errors.Join(err, errors.New("test sandbox cleanup failed"))
		}
	}()
	process, err := container.Start(ctx, gateway.StartRequest{
		Args: command, Cwd: "/app", User: "0:0", Env: metadata.Config.Env,
		SecurityMode: pb.SecurityMode_SANDBOX,
		Stdout:       writerCloser{stdout}, Stderr: writerCloser{stderr},
	})
	if err != nil {
		return errors.New("test process could not be started")
	}
	if err := process.Wait(); err != nil {
		var exit *gatepb.ExitError
		if errors.As(err, &exit) {
			return fmt.Errorf("tests failed (exit %d)", exit.ExitCode)
		}
		return errors.New("test process failed or was interrupted")
	}
	if ctx.Err() != nil {
		return errors.New("test execution timed out or was cancelled")
	}
	return nil
}

type writerCloser struct{ io.Writer }

func (writerCloser) Close() error { return nil }

func run() error {
	flags := flag.NewFlagSet("cloudlab-test", flag.ContinueOnError)
	source := flags.String("source", ".", "Git checkout root")
	timeout := flags.Duration("timeout", 20*time.Minute, "test deadline (maximum 20m)")
	version := flags.Bool("version", false, "print the compiled executor source checksum")
	if flags.Parse(os.Args[1:]) != nil {
		return errors.New("invalid test execution arguments")
	}
	if *version {
		fmt.Println(sourceSHA256)
		return nil
	}
	if len(flags.Args()) == 0 || len(flags.Args()) > 32 || *timeout <= 0 || *timeout > 20*time.Minute {
		return errors.New("usage: cloudlab-test [--source checkout] -- command [arguments]")
	}
	for _, arg := range flags.Args() {
		if len(arg) > 4096 || strings.ContainsRune(arg, 0) {
			return errors.New("invalid test command")
		}
	}
	cfg, err := readConfiguration("/run/cloudlab-test/config/config.json")
	if err != nil {
		return err
	}
	snapshot, err := sourceSnapshot(*source)
	if err != nil {
		return err
	}
	defer os.RemoveAll(snapshot)
	// Auth provider state is local to this execution, never inherited from the runner's Docker configuration.
	state, err := os.MkdirTemp("/tmp", "cloudlab-test-auth-")
	if err != nil {
		return errors.New("test execution state unavailable")
	}
	defer os.RemoveAll(state)
	os.Setenv("DOCKER_CONFIG", state)
	auth, err := registryAuthentication("/run/cloudlab-test/registry/config.json", cfg.Image)
	if err != nil {
		return err
	}
	signalContext, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	ctx, cancel := context.WithTimeout(signalContext, *timeout)
	defer cancel()
	client, err := buildkit.New(ctx, endpoint)
	if err != nil {
		return errors.New("test sandbox service unavailable")
	}
	defer client.Close()
	local, err := fsutil.NewFS(snapshot)
	if err != nil {
		return errors.New("test source snapshot unavailable")
	}
	_, err = client.Build(ctx, buildkit.SolveOpt{
		LocalMounts: map[string]fsutil.FS{"source": local}, Session: []session.Attachable{auth},
	}, "cloudlab-test", func(ctx context.Context, gatewayClient gateway.Client) (*gateway.Result, error) {
		if err := executeTests(ctx, gatewayClient, cfg.Image, flags.Args(), os.Stdout, os.Stderr); err != nil {
			return nil, err
		}
		return gateway.NewResult(), nil
	}, nil)
	if err != nil {
		return errors.New("offline test execution failed")
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
