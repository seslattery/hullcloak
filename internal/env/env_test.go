package env

import (
	"slices"
	"strings"
	"testing"
)

func TestIsSecret(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		// suffix matches
		{"OPENAI_API_KEY", true},
		{"MY_TOKEN", true},
		{"DB_SECRET", true},
		{"MY_PASSWORD", true},
		{"SOME_CREDENTIAL", true},
		{"SOME_CREDENTIALS", true},
		{"BASIC_AUTH", true},
		{"SSH_PRIVATE", true},
		{"my_token", true},

		// exact name matches (not caught by suffixes)
		{"AWS_ACCESS_KEY_ID", true},
		{"DOCKER_AUTH_CONFIG", true},
		{"KUBECONFIG", true},
		{"kubeconfig", true},
		{"PGPASSWORD", true},
		{"MYSQL_PWD", true},

		// vars caught by both suffix and exact name
		{"GITHUB_TOKEN", true},
		{"DOPPLER_TOKEN", true},
		{"AWS_SECRET_ACCESS_KEY", true},
		{"DOCKER_PASSWORD", true},

		// safe vars
		{"PATH", false},
		{"HOME", false},
		{"USER", false},
		{"SHELL", false},
		{"EDITOR", false},
		{"TERM", false},
		{"LANG", false},
		{"NODE_ENV", false},
		{"GOPATH", false},
		{"GOROOT", false},
		{"DEBUG", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			if got := IsSecret(tt.key); got != tt.want {
				t.Errorf("IsSecret(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func envMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, e := range env {
		k, v, _ := strings.Cut(e, "=")
		m[k] = v
	}
	return m
}

func envCount(env []string, key string) int {
	n := 0
	for _, e := range env {
		if strings.HasPrefix(e, key+"=") {
			n++
		}
	}
	return n
}

func TestBuild(t *testing.T) {
	tests := []struct {
		name           string
		parent         []string
		opts           Options
		wantPresent    map[string]string // key → exact value
		wantAbsent     []string          // keys that must not appear
		wantNoDupes    []string          // keys that must appear exactly once
	}{
		{
			name: "strips secrets, sets proxy, sets tmp",
			parent: []string{
				"PATH=/usr/bin", "HOME=/home/user", "NODE_ENV=dev",
				"OPENAI_API_KEY=sk-secret", "GITHUB_TOKEN=ghp_test",
				"AWS_SECRET_ACCESS_KEY=x", "MY_PASSWORD=hunter2", "KUBECONFIG=/k",
				"HTTP_PROXY=http://old:1234", "NO_PROXY=localhost",
			},
			opts: Options{
				ProxyAddr: "http://127.0.0.1:9999",
				TmpDir:    "/p/.hullcloak-tmp/tmp/",
				CacheDir:  "/p/.hullcloak-tmp/cache/",
			},
			wantPresent: map[string]string{
				"PATH": "/usr/bin", "HOME": "/home/user", "NODE_ENV": "dev",
				"HTTP_PROXY": "http://127.0.0.1:9999", "HTTPS_PROXY": "http://127.0.0.1:9999",
				"http_proxy": "http://127.0.0.1:9999", "https_proxy": "http://127.0.0.1:9999",
				"NO_PROXY": "", "no_proxy": "", "ALL_PROXY": "", "all_proxy": "",
				"TMPDIR": "/p/.hullcloak-tmp/tmp/", "XDG_CACHE_HOME": "/p/.hullcloak-tmp/cache/",
			},
			wantAbsent:  []string{"OPENAI_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "MY_PASSWORD", "KUBECONFIG"},
			wantNoDupes: []string{"HTTP_PROXY", "NO_PROXY"},
		},
		{
			name:   "passthrough preserves secret",
			parent: []string{"ANTHROPIC_API_KEY=sk-ant", "OPENAI_API_KEY=sk-oa", "PATH=/usr/bin"},
			opts:   Options{ProxyAddr: "http://127.0.0.1:9999", EnvPassthrough: []string{"ANTHROPIC_API_KEY"}},
			wantPresent: map[string]string{"ANTHROPIC_API_KEY": "sk-ant", "PATH": "/usr/bin"},
			wantAbsent:  []string{"OPENAI_API_KEY"},
		},
		{
			name:        "passthrough case-insensitive",
			parent:      []string{"my_token=val"},
			opts:        Options{ProxyAddr: "http://127.0.0.1:9999", EnvPassthrough: []string{"MY_TOKEN"}},
			wantPresent: map[string]string{"my_token": "val"},
		},
		{
			name: "lowercase proxy vars replaced",
			parent: []string{
				"PATH=/usr/bin",
				"http_proxy=http://old:1234", "https_proxy=http://old:1234",
				"no_proxy=localhost", "all_proxy=socks5://old:1080",
			},
			opts:        Options{ProxyAddr: "http://127.0.0.1:9999"},
			wantPresent: map[string]string{"http_proxy": "http://127.0.0.1:9999", "no_proxy": ""},
			wantNoDupes: []string{"http_proxy", "no_proxy", "all_proxy"},
		},
		{
			name:   "existing tmpdir overwritten",
			parent: []string{"PATH=/usr/bin", "TMPDIR=/old/tmp", "XDG_CACHE_HOME=/old/cache"},
			opts:   Options{ProxyAddr: "http://127.0.0.1:9999", TmpDir: "/new/tmp/", CacheDir: "/new/cache/"},
			wantPresent: map[string]string{"TMPDIR": "/new/tmp/", "XDG_CACHE_HOME": "/new/cache/"},
			wantNoDupes: []string{"TMPDIR", "XDG_CACHE_HOME"},
		},
		{
			name:       "no tmpdir when empty",
			parent:     []string{"PATH=/usr/bin"},
			opts:       Options{ProxyAddr: "http://127.0.0.1:9999"},
			wantAbsent: []string{"TMPDIR", "XDG_CACHE_HOME"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Build(tt.parent, tt.opts)
			m := envMap(result)

			for k, want := range tt.wantPresent {
				got, ok := m[k]
				if !ok {
					t.Errorf("%s should be present", k)
				} else if got != want {
					t.Errorf("%s = %q, want %q", k, got, want)
				}
			}
			for _, k := range tt.wantAbsent {
				if _, ok := m[k]; ok {
					t.Errorf("%s should be absent", k)
				}
			}
			for _, k := range tt.wantNoDupes {
				if n := envCount(result, k); n != 1 {
					t.Errorf("%s appears %d times, want 1", k, n)
				}
			}
		})
	}
}

func TestStripped(t *testing.T) {
	tests := []struct {
		name        string
		parent      []string
		passthrough []string
		want        []string
	}{
		{
			name:   "returns stripped secret names",
			parent: []string{"PATH=/usr/bin", "OPENAI_API_KEY=sk", "GITHUB_TOKEN=ghp", "HOME=/h", "MY_PASSWORD=x"},
			want:   []string{"OPENAI_API_KEY", "GITHUB_TOKEN", "MY_PASSWORD"},
		},
		{
			name:        "respects passthrough",
			parent:      []string{"OPENAI_API_KEY=sk", "GITHUB_TOKEN=ghp"},
			passthrough: []string{"OPENAI_API_KEY"},
			want:        []string{"GITHUB_TOKEN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Stripped(tt.parent, tt.passthrough)
			if len(got) != len(tt.want) {
				t.Fatalf("Stripped returned %v, want %v", got, tt.want)
			}
			for _, w := range tt.want {
				if !slices.Contains(got, w) {
					t.Errorf("missing %q in stripped list", w)
				}
			}
		})
	}
}
