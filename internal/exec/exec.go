package exec

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/seslattery/hullcloak/internal/config"
	"github.com/seslattery/hullcloak/internal/env"
	"github.com/seslattery/hullcloak/internal/proxy"
	"github.com/seslattery/hullcloak/internal/sandbox"
)

// Options configures a sandboxed command execution.
type Options struct {
	Config  *config.Config
	Command []string
	Verbose bool
	Stdin   io.Reader
	Stdout  io.Writer
	Stderr  io.Writer
}

// Result holds the outcome of a sandboxed command.
type Result struct {
	ExitCode int
	Profile  string
}

// Run executes a command inside a sandbox with proxy-based network control.
func Run(ctx context.Context, opts *Options) (Result, error) {
	if opts.Config == nil {
		return Result{}, fmt.Errorf("config is required")
	}
	if len(opts.Command) == 0 {
		return Result{}, fmt.Errorf("command is required")
	}
	if opts.Stdin == nil {
		opts.Stdin = os.Stdin
	}
	if opts.Stdout == nil {
		opts.Stdout = os.Stdout
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}

	cwd, err := os.Getwd()
	if err != nil {
		return Result{}, fmt.Errorf("getwd: %w", err)
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		return Result{}, fmt.Errorf("eval symlinks: %w", err)
	}

	base := filepath.Join(cwd, ".hullcloak-tmp")
	tmpDir := filepath.Join(base, "tmp")
	cacheDir := filepath.Join(base, "cache")
	for _, d := range []string{base, tmpDir, cacheDir} {
		if err := ensurePrivateDir(d); err != nil {
			return Result{}, err
		}
	}

	srv, err := proxy.New(proxy.Options{
		Allow:      opts.Config.Allow,
		AllowPorts: opts.Config.AllowPorts,
		Verbose:    opts.Verbose,
	})
	if err != nil {
		return Result{}, fmt.Errorf("proxy init: %w", err)
	}
	if err := srv.Start(); err != nil {
		return Result{}, fmt.Errorf("proxy start: %w", err)
	}
	defer srv.Close() //nolint:errcheck

	_, portStr, err := net.SplitHostPort(srv.Addr)
	if err != nil {
		return Result{}, fmt.Errorf("parse proxy addr: %w", err)
	}
	proxyPort, err := strconv.Atoi(portStr)
	if err != nil {
		return Result{}, fmt.Errorf("parse proxy port: %w", err)
	}

	parentEnv := os.Environ()
	if opts.Verbose {
		stripped := env.Stripped(parentEnv, opts.Config.EnvPassthrough)
		if len(stripped) > 0 {
			fmt.Fprintf(opts.Stderr, "hc: stripped env vars: %v\n", stripped) //nolint:errcheck
		}
	}

	childEnv := env.Build(parentEnv, env.Options{
		ProxyAddr:      "http://" + srv.Addr,
		TmpDir:         tmpDir + "/",
		CacheDir:       cacheDir,
		EnvPassthrough: opts.Config.EnvPassthrough,
	})

	profile, err := sandbox.Generate(&sandbox.Params{
		Tier:             opts.Config.Tier,
		CWD:              cwd,
		ProxyPort:        proxyPort,
		AllowRead:        opts.Config.AllowRead,
		AllowWrite:       opts.Config.AllowWrite,
		AllowUnixSockets: opts.Config.AllowUnixSockets,
	})
	if err != nil {
		return Result{}, fmt.Errorf("generate profile: %w", err)
	}

	return runSandbox(ctx, opts, childEnv, cwd, profile)
}

// ProfileOnly generates a sandbox profile without executing a command.
func ProfileOnly(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("config is required")
	}

	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", fmt.Errorf("eval symlinks: %w", err)
	}

	return sandbox.Generate(&sandbox.Params{
		Tier:             cfg.Tier,
		CWD:              cwd,
		ProxyPort:        1,
		AllowRead:        cfg.AllowRead,
		AllowWrite:       cfg.AllowWrite,
		AllowUnixSockets: cfg.AllowUnixSockets,
	})
}

func runSandbox(ctx context.Context, opts *Options, childEnv []string, cwd, profile string) (Result, error) {
	f, err := os.CreateTemp("", "hullcloak-*.sbpl")
	if err != nil {
		return Result{}, fmt.Errorf("create profile file: %w", err)
	}
	profilePath := f.Name()
	defer os.Remove(profilePath) //nolint:errcheck

	if _, err := f.WriteString(profile); err != nil {
		f.Close() //nolint:errcheck,gosec
		return Result{}, fmt.Errorf("write profile: %w", err)
	}
	if err := f.Close(); err != nil {
		return Result{}, fmt.Errorf("close profile: %w", err)
	}

	args := append([]string{"-f", profilePath, "--"}, opts.Command...)
	cmd := exec.CommandContext(ctx, "sandbox-exec", args...) //nolint:gosec
	cmd.Env = childEnv
	cmd.Dir = cwd
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	done := make(chan struct{})

	if err := cmd.Start(); err != nil {
		signal.Stop(sigCh)
		return Result{}, fmt.Errorf("start sandbox-exec: %w", err)
	}

	go func() {
		count := 0
		for {
			select {
			case <-done:
				return
			case sig := <-sigCh:
				count++
				if count >= 2 {
					cmd.Process.Kill() //nolint:errcheck,gosec
					return
				}
				cmd.Process.Signal(sig) //nolint:errcheck,gosec
			}
		}
	}()

	err = cmd.Wait()
	signal.Stop(sigCh)
	close(done)

	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return Result{ExitCode: exitErr.ExitCode(), Profile: profile}, nil
		}
		return Result{}, fmt.Errorf("wait: %w", err)
	}
	return Result{ExitCode: 0, Profile: profile}, nil
}

func ensurePrivateDir(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return os.Mkdir(path, 0o700)
	}
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing for safety", path)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", path)
	}
	stat, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("%s: cannot determine owner", path)
	}
	if stat.Uid != uint32(os.Getuid()) { //nolint:gosec
		return fmt.Errorf("%s is owned by uid %d, not current user %d", path, stat.Uid, os.Getuid())
	}
	return nil
}
