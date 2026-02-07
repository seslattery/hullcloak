//go:build darwin

package exec

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seslattery/hullcloak/internal/config"
)

func skipIfNoSandbox(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		t.Skip("sandbox-exec not available")
	}
}

func testConfig() *config.Config {
	return &config.Config{
		Version:    config.CurrentVersion,
		Tier:       config.TierStrict,
		Allow:      []string{"example.com"},
		AllowPorts: []int{443, 80},
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chdir(orig) }) //nolint:errcheck
}

func TestRun(t *testing.T) {
	skipIfNoSandbox(t)

	tests := []struct {
		name     string
		command  []string
		wantCode int
	}{
		{"true exits 0", []string{"/usr/bin/true"}, 0},
		{"false exits 1", []string{"/usr/bin/false"}, 1},
		{"echo runs", []string{"/bin/echo", "hello"}, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chdir(t, t.TempDir())
			var stdout, stderr bytes.Buffer
			res, err := Run(context.Background(), &Options{
				Config:  testConfig(),
				Command: tt.command,
				Stdout:  &stdout,
				Stderr:  &stderr,
			})
			if err != nil {
				t.Fatalf("Run() error: %v\nstderr: %s", err, stderr.String())
			}
			if res.ExitCode != tt.wantCode {
				t.Errorf("exit code = %d, want %d", res.ExitCode, tt.wantCode)
			}
		})
	}
}

func TestRunEchoOutput(t *testing.T) {
	skipIfNoSandbox(t)
	chdir(t, t.TempDir())

	var stdout bytes.Buffer
	res, err := Run(context.Background(), &Options{
		Config:  testConfig(),
		Command: []string{"/bin/echo", "hello from sandbox"},
		Stdout:  &stdout,
		Stderr:  &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d", res.ExitCode)
	}
	if got := strings.TrimSpace(stdout.String()); got != "hello from sandbox" {
		t.Errorf("stdout = %q, want %q", got, "hello from sandbox")
	}
}

func TestRunEnvStripping(t *testing.T) {
	skipIfNoSandbox(t)
	chdir(t, t.TempDir())

	t.Setenv("OPENAI_API_KEY", "sk-test-strip")
	t.Setenv("GITHUB_TOKEN", "ghp-test-strip")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "aws-test-strip")

	var stdout bytes.Buffer
	res, err := Run(context.Background(), &Options{
		Config:  testConfig(),
		Command: []string{"/usr/bin/env"},
		Stdout:  &stdout,
		Stderr:  &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d", res.ExitCode)
	}

	output := stdout.String()
	for _, bad := range []string{"OPENAI_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY"} {
		if strings.Contains(output, bad+"=") {
			t.Errorf("child env should not contain %s", bad)
		}
	}
	if !strings.Contains(output, "HTTP_PROXY=http://127.0.0.1:") {
		t.Error("child env should contain HTTP_PROXY")
	}
}

func TestRunCreatesTmpDirs(t *testing.T) {
	skipIfNoSandbox(t)
	dir := t.TempDir()
	chdir(t, dir)

	_, err := Run(context.Background(), &Options{
		Config:  testConfig(),
		Command: []string{"/usr/bin/true"},
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}

	dir, _ = filepath.EvalSymlinks(dir)
	for _, sub := range []string{"tmp", "cache"} {
		d := filepath.Join(dir, ".hullcloak-tmp", sub)
		info, err := os.Stat(d)
		if err != nil {
			t.Errorf("%s should exist: %v", sub, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("%s should be a directory", sub)
		}
		if perm := info.Mode().Perm(); perm != 0o700 {
			t.Errorf("%s perm = %o, want 700", sub, perm)
		}
	}
}

func TestRunProfileReturned(t *testing.T) {
	skipIfNoSandbox(t)
	chdir(t, t.TempDir())

	res, err := Run(context.Background(), &Options{
		Config:  testConfig(),
		Command: []string{"/usr/bin/true"},
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("Run() error: %v", err)
	}
	if !strings.Contains(res.Profile, "(version 1)") {
		t.Error("profile should contain (version 1)")
	}
	if !strings.Contains(res.Profile, "HULLCLOAK_SANDBOX_VIOLATION") {
		t.Error("profile should contain sandbox violation message")
	}
}

func TestProfileOnly(t *testing.T) {
	profile, err := ProfileOnly(testConfig())
	if err != nil {
		t.Fatalf("ProfileOnly() error: %v", err)
	}
	if !strings.Contains(profile, "(version 1)") {
		t.Error("profile should contain (version 1)")
	}
}

func TestRunTLSThroughProxy(t *testing.T) {
	skipIfNoSandbox(t)
	if os.Getenv("HC_SMOKE_NET") == "" {
		t.Skip("set HC_SMOKE_NET=1 to run network smoke tests")
	}
	chdir(t, t.TempDir())

	var stdout, stderr bytes.Buffer
	res, err := Run(context.Background(), &Options{
		Config:  testConfig(),
		Command: []string{"/usr/bin/curl", "-fsS", "--connect-timeout", "5", "--max-time", "15", "https://example.com"},
		Stdout:  &stdout,
		Stderr:  &stderr,
	})
	if err != nil {
		t.Fatalf("Run() error: %v\nstderr: %s", err, stderr.String())
	}
	if res.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0\nstderr: %s", res.ExitCode, stderr.String())
	}
	if stdout.Len() == 0 {
		t.Error("expected non-empty response from example.com")
	}
}

func TestRunSymlinkGuard(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	link := filepath.Join(dir, ".hullcloak-tmp")
	if err := os.Symlink("/tmp", link); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err := Run(context.Background(), &Options{
		Config:  testConfig(),
		Command: []string{"/usr/bin/true"},
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
	})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}

func TestRunSubdirSymlinkGuard(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	base := filepath.Join(dir, ".hullcloak-tmp")
	os.Mkdir(base, 0o700) //nolint:errcheck
	if err := os.Symlink("/tmp", filepath.Join(base, "tmp")); err != nil {
		t.Fatalf("create symlink: %v", err)
	}

	_, err := Run(context.Background(), &Options{
		Config:  testConfig(),
		Command: []string{"/usr/bin/true"},
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
	})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Errorf("expected symlink error, got: %v", err)
	}
}

func TestRunValidation(t *testing.T) {
	tests := []struct {
		name string
		opts *Options
		want string
	}{
		{"nil config", &Options{Command: []string{"true"}}, "config is required"},
		{"no command", &Options{Config: testConfig()}, "command is required"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Run(context.Background(), tt.opts)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("got error %v, want containing %q", err, tt.want)
			}
		})
	}
}
