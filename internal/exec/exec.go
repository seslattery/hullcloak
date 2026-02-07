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

	"github.com/creack/pty"
	"golang.org/x/term"

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

// CanonicalCWD returns the current working directory with symlinks resolved.
func CanonicalCWD() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("getwd: %w", err)
	}
	cwd, err = filepath.EvalSymlinks(cwd)
	if err != nil {
		return "", fmt.Errorf("eval symlinks: %w", err)
	}
	return cwd, nil
}

// WorkDirs returns the base, tmp, and cache directories under cwd/.hullcloak-tmp/.
func WorkDirs(cwd string) (base, tmpDir, cacheDir string) {
	base = filepath.Join(cwd, ".hullcloak-tmp")
	return base, filepath.Join(base, "tmp"), filepath.Join(base, "cache")
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

	cwd, err := CanonicalCWD()
	if err != nil {
		return Result{}, err
	}

	base, tmpDir, cacheDir := WorkDirs(cwd)
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

	if isTTY(opts.Stdin) {
		return runSandboxPTY(ctx, opts, childEnv, cwd, tmpDir, profile)
	}
	return runSandboxPipes(ctx, opts, childEnv, cwd, tmpDir, profile)
}

// ProfileOnly generates a sandbox profile without executing a command.
func ProfileOnly(cfg *config.Config) (string, error) {
	if cfg == nil {
		return "", fmt.Errorf("config is required")
	}

	cwd, err := CanonicalCWD()
	if err != nil {
		return "", err
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

const sandboxExecPath = "/usr/bin/sandbox-exec"

func writeProfile(tmpDir, profile string) (string, error) {
	f, err := os.CreateTemp(tmpDir, "hullcloak-*.sbpl")
	if err != nil {
		return "", fmt.Errorf("create profile file: %w", err)
	}
	path := f.Name()
	if _, err := f.WriteString(profile); err != nil {
		f.Close()       //nolint:errcheck,gosec
		os.Remove(path) //nolint:errcheck
		return "", fmt.Errorf("write profile: %w", err)
	}
	if err := f.Close(); err != nil {
		os.Remove(path) //nolint:errcheck
		return "", fmt.Errorf("close profile: %w", err)
	}
	return path, nil
}

func runSandboxPTY(ctx context.Context, opts *Options, childEnv []string, cwd, tmpDir, profile string) (Result, error) {
	profilePath, err := writeProfile(tmpDir, profile)
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(profilePath) //nolint:errcheck

	args := append([]string{"-f", profilePath, "--"}, opts.Command...)
	cmd := exec.CommandContext(ctx, sandboxExecPath, args...) //nolint:gosec
	cmd.Env = childEnv
	cmd.Dir = cwd

	ptmx, err := pty.Start(cmd)
	if err != nil {
		return Result{}, fmt.Errorf("start sandbox-exec with pty: %w", err)
	}

	done := make(chan struct{})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGWINCH)
	go func() {
		for {
			select {
			case <-done:
				return
			case _, ok := <-sigCh:
				if !ok {
					return
				}
				pty.InheritSize(os.Stdin, ptmx) //nolint:errcheck
			}
		}
	}()
	sigCh <- syscall.SIGWINCH

	oldState, err := term.MakeRaw(int(os.Stdin.Fd())) //nolint:gosec
	if err != nil {
		oldState = nil
	}

	go func() {
		io.Copy(ptmx, os.Stdin) //nolint:errcheck
	}()

	go func() {
		io.Copy(opts.Stdout, ptmx) //nolint:errcheck
	}()

	waitErr := cmd.Wait()

	close(done)
	signal.Stop(sigCh)
	ptmx.Close() //nolint:errcheck

	if oldState != nil {
		term.Restore(int(os.Stdin.Fd()), oldState) //nolint:errcheck,gosec
	}

	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			return Result{ExitCode: exitErr.ExitCode(), Profile: profile}, nil
		}
		return Result{}, fmt.Errorf("wait: %w", waitErr)
	}
	return Result{ExitCode: 0, Profile: profile}, nil
}

func runSandboxPipes(ctx context.Context, opts *Options, childEnv []string, cwd, tmpDir, profile string) (Result, error) {
	profilePath, err := writeProfile(tmpDir, profile)
	if err != nil {
		return Result{}, err
	}
	defer os.Remove(profilePath) //nolint:errcheck

	args := append([]string{"-f", profilePath, "--"}, opts.Command...)
	cmd := exec.CommandContext(ctx, sandboxExecPath, args...) //nolint:gosec
	cmd.Env = childEnv
	cmd.Dir = cwd
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	doneCh := make(chan struct{})

	if err := cmd.Start(); err != nil {
		signal.Stop(sigCh)
		return Result{}, fmt.Errorf("start sandbox-exec: %w", err)
	}

	go func() {
		count := 0
		for {
			select {
			case <-doneCh:
				return
			case sig := <-sigCh:
				count++
				s, ok := sig.(syscall.Signal)
				if !ok {
					continue
				}
				if count >= 2 {
					s = syscall.SIGKILL
				}
				syscall.Kill(-cmd.Process.Pid, s) //nolint:errcheck,gosec
				if s == syscall.SIGKILL {
					return
				}
			}
		}
	}()

	waitErr := cmd.Wait()
	signal.Stop(sigCh)
	close(doneCh)

	if waitErr != nil {
		if exitErr, ok := waitErr.(*exec.ExitError); ok {
			return Result{ExitCode: exitErr.ExitCode(), Profile: profile}, nil
		}
		return Result{}, fmt.Errorf("wait: %w", waitErr)
	}
	return Result{ExitCode: 0, Profile: profile}, nil
}

func isTTY(r io.Reader) bool {
	f, ok := r.(*os.File)
	return ok && term.IsTerminal(int(f.Fd())) //nolint:gosec
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
	if perm := fi.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(path, 0o700); err != nil {
			return fmt.Errorf("%s has perm %o and chmod failed: %w", path, perm, err)
		}
	}
	return nil
}
