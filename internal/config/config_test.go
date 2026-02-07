package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad_MinimalValid(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
version: 1
tier: strict
allow:
  - api.anthropic.com
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 1 {
		t.Errorf("version = %d, want 1", cfg.Version)
	}
	if cfg.Tier != TierStrict {
		t.Errorf("tier = %q, want strict", cfg.Tier)
	}
	if len(cfg.Allow) != 1 || cfg.Allow[0] != "api.anthropic.com" {
		t.Errorf("allow = %v, want [api.anthropic.com]", cfg.Allow)
	}
	if len(cfg.AllowPorts) != 2 || cfg.AllowPorts[0] != 443 || cfg.AllowPorts[1] != 80 {
		t.Errorf("allow_ports = %v, want [443 80]", cfg.AllowPorts)
	}
}

func TestLoad_FullConfig(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
version: 1
tier: permissive
allow:
  - api.anthropic.com
  - "*.githubusercontent.com"
allow_ports: [443, 80, 8080]
allow_read:
  - /usr/local/share
allow_write:
  - /tmp
allow_unix_sockets:
  - /var/run/docker.sock
env_passthrough:
  - ANTHROPIC_API_KEY
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tier != TierPermissive {
		t.Errorf("tier = %q, want permissive", cfg.Tier)
	}
	if len(cfg.AllowPorts) != 3 {
		t.Errorf("allow_ports len = %d, want 3", len(cfg.AllowPorts))
	}
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
version: 1
allow:
  - api.anthropic.com
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Tier != TierStrict {
		t.Errorf("tier = %q, want strict", cfg.Tier)
	}
	if len(cfg.AllowPorts) != 2 || cfg.AllowPorts[0] != 443 || cfg.AllowPorts[1] != 80 {
		t.Errorf("allow_ports = %v, want [443 80]", cfg.AllowPorts)
	}
}

func TestLoad_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		config  string
		wantErr string
	}{
		// version
		{"missing version", "allow: [api.example.com]", "version is required"},
		{"unsupported version", "version: 99\nallow: [api.example.com]", "unsupported config version"},

		// tier
		{"unknown tier", "version: 1\ntier: paranoid\nallow: [api.example.com]", "unknown tier"},

		// allow list
		{"empty allow", "version: 1\nallow: []", "must not be empty"},
		{"no allow", "version: 1", "must not be empty"},

		// hostname: IP literals
		{"ipv4 literal", "version: 1\nallow: [1.2.3.4]", "IP literals"},
		{"ipv4 private", "version: 1\nallow: [192.168.1.1]", "IP literals"},
		{"ipv6 bare", "version: 1\nallow: [\"::1\"]", "IP literals"},
		{"ipv6 bracketed", "version: 1\nallow: [\"[::1]\"]", "invalid characters"},
		{"ipv6 with port", "version: 1\nallow: [\"[::1]:443\"]", "invalid characters"},
		{"host with port", "version: 1\nallow: [\"api.example.com:443\"]", "without port"},

		// hostname: format
		{"url scheme http", "version: 1\nallow: [\"http://api.example.com\"]", "not a URL"},
		{"url scheme https", "version: 1\nallow: [\"https://api.example.com\"]", "not a URL"},
		{"whitespace", "version: 1\nallow: [\"api. example.com\"]", "invalid characters"},
		{"empty string", "version: 1\nallow: [\"\", api.example.com]", "empty hostname"},
		{"double dots", "version: 1\nallow: [\"api..example.com\"]", "not a valid hostname"},
		{"multiple trailing dots", "version: 1\nallow: [\"example.com..\"]", "not a valid hostname"},
		{"leading hyphen", "version: 1\nallow: [\"-example.com\"]", "not a valid hostname"},
		{"trailing hyphen", "version: 1\nallow: [\"example-.com\"]", "not a valid hostname"},
		{"dotless hostname", "version: 1\nallow: [localhost]", "at least two labels"},
		{"single label", "version: 1\nallow: [com]", "at least two labels"},

		// wildcards
		{"wildcard not leftmost", "version: 1\nallow: [\"foo.*.example.com\"]", "leftmost label"},
		{"multiple wildcards", "version: 1\nallow: [\"*.*.example.com\"]", "one wildcard"},
		{"bare star", "version: 1\nallow: [\"*\"]", "leftmost label"},
		{"wildcard dot only", "version: 1\nallow: [\"*.\"]", "leftmost label"},
		{"wildcard double dot", "version: 1\nallow: [\"*..example.com\"]", "not a valid hostname"},
		{"wildcard tld", "version: 1\nallow: [\"*.com\"]", "second-level domain"},

		// paths
		{"relative allow_read", "version: 1\nallow: [api.example.com]\nallow_read: [relative/path]", "must be absolute"},
		{"relative allow_write", "version: 1\nallow: [api.example.com]\nallow_write: [relative/path]", "must be absolute"},

		// unix sockets
		{"unix sockets strict", "version: 1\ntier: strict\nallow: [api.example.com]\nallow_unix_sockets: [/var/run/docker.sock]", "permissive"},
		{"unix socket relative", "version: 1\ntier: permissive\nallow: [api.example.com]\nallow_unix_sockets: [relative/sock]", "must be absolute"},
		{"unix socket empty", "version: 1\ntier: permissive\nallow: [api.example.com]\nallow_unix_sockets: [\"\"]", "empty path"},
		{"path with null", "version: 1\nallow: [api.example.com]\nallow_write: [\"/tmp/\\x00bad\"]", "control characters"},

		// ports
		{"port zero", "version: 1\nallow: [api.example.com]\nallow_ports: [0, 443]", "not a valid port"},
		{"port negative", "version: 1\nallow: [api.example.com]\nallow_ports: [-1, 443]", "not a valid port"},
		{"port too high", "version: 1\nallow: [api.example.com]\nallow_ports: [443, 65536]", "not a valid port"},

		// env passthrough
		{"env empty", "version: 1\nallow: [api.example.com]\nenv_passthrough: [\"\"]", "invalid variable name"},
		{"env with equals", "version: 1\nallow: [api.example.com]\nenv_passthrough: [\"BAD=VALUE\"]", "invalid variable name"},
		{"env with space", "version: 1\nallow: [api.example.com]\nenv_passthrough: [\"HAS SPACE\"]", "invalid variable name"},
		{"env starts with digit", "version: 1\nallow: [api.example.com]\nenv_passthrough: [9KEY]", "invalid variable name"},
		{"env with hyphen", "version: 1\nallow: [api.example.com]\nenv_passthrough: [MY-KEY]", "invalid variable name"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tt.config))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error = %q, want substring %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestLoad_ValidConfigs(t *testing.T) {
	tests := []struct {
		name   string
		config string
	}{
		{"permissive tier", "version: 1\ntier: permissive\nallow: [api.example.com]"},
		{"valid wildcard", "version: 1\nallow: [\"*.example.com\"]"},
		{"absolute paths", "version: 1\nallow: [api.example.com]\nallow_read: [/usr/local/share]\nallow_write: [/tmp]"},
		{"tilde paths", "version: 1\nallow: [api.example.com]\nallow_write: [~/projects]"},
		{"unix sockets permissive", "version: 1\ntier: permissive\nallow: [api.example.com]\nallow_unix_sockets: [/var/run/docker.sock]"},
		{"valid ports", "version: 1\nallow: [api.example.com]\nallow_ports: [1, 443, 80, 65535]"},
		{"empty ports explicit", "version: 1\nallow: [api.example.com]\nallow_ports: []"},
		{"env passthrough", "version: 1\nallow: [api.example.com]\nenv_passthrough: [ANTHROPIC_API_KEY, OPENAI_API_KEY]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Load(writeConfig(t, tt.config)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestLoad_Normalization(t *testing.T) {
	t.Run("hostname lowercased", func(t *testing.T) {
		cfg, _ := Load(writeConfig(t, "version: 1\nallow: [API.Anthropic.COM]"))
		if cfg.Allow[0] != "api.anthropic.com" {
			t.Errorf("got %q, want api.anthropic.com", cfg.Allow[0])
		}
	})

	t.Run("trailing dot stripped", func(t *testing.T) {
		cfg, _ := Load(writeConfig(t, "version: 1\nallow: [\"api.example.com.\"]"))
		if cfg.Allow[0] != "api.example.com" {
			t.Errorf("got %q, want api.example.com", cfg.Allow[0])
		}
	})

	t.Run("duplicates deduped", func(t *testing.T) {
		cfg, _ := Load(writeConfig(t, "version: 1\nallow: [api.example.com, api.example.com, API.Example.Com]"))
		if len(cfg.Allow) != 1 {
			t.Errorf("got %d entries, want 1", len(cfg.Allow))
		}
	})

	t.Run("normalized duplicates deduped", func(t *testing.T) {
		cfg, _ := Load(writeConfig(t, "version: 1\nallow: [\"API.Example.COM.\", api.example.com]"))
		if len(cfg.Allow) != 1 {
			t.Errorf("got %d entries, want 1", len(cfg.Allow))
		}
	})

	t.Run("path dedup", func(t *testing.T) {
		cfg, _ := Load(writeConfig(t, "version: 1\nallow: [api.example.com]\nallow_write: [/tmp, /tmp]"))
		if len(cfg.AllowWrite) != 1 {
			t.Errorf("got %d entries, want 1", len(cfg.AllowWrite))
		}
	})

	t.Run("explicit empty ports not overridden", func(t *testing.T) {
		cfg, _ := Load(writeConfig(t, "version: 1\nallow: [api.example.com]\nallow_ports: []"))
		if len(cfg.AllowPorts) != 0 {
			t.Errorf("got %v, want empty", cfg.AllowPorts)
		}
	})

	t.Run("tilde expanded", func(t *testing.T) {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Skip("no home dir")
		}
		cfg, _ := Load(writeConfig(t, "version: 1\nallow: [api.example.com]\nallow_write: [~/projects]"))
		want := filepath.Join(home, "projects")
		if cfg.AllowWrite[0] != want {
			t.Errorf("got %q, want %q", cfg.AllowWrite[0], want)
		}
	})
}

func TestLoad_EdgeCases(t *testing.T) {
	t.Run("file not found", func(t *testing.T) {
		if _, err := Load("/nonexistent/config.yaml"); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("invalid yaml", func(t *testing.T) {
		if _, err := Load(writeConfig(t, "{{{invalid")); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestValidateHost_Standalone(t *testing.T) {
	if err := validateHost("API.Example.COM"); err != nil {
		t.Errorf("should accept uppercase: %v", err)
	}
	if err := validateHost("api.example.com."); err != nil {
		t.Errorf("should accept trailing dot: %v", err)
	}
}

func TestMatchHost(t *testing.T) {
	tests := []struct {
		pattern, host string
		want          bool
	}{
		{"api.example.com", "api.example.com", true},
		{"api.example.com", "API.Example.COM", true},
		{"api.example.com", "other.example.com", false},
		{"*.example.com", "foo.example.com", true},
		{"*.example.com", "bar.example.com", true},
		{"*.example.com", "example.com", false},
		{"*.example.com", "foo.bar.example.com", false},
		{"*.example.com", "example.com.evil.com", false},
		{"*.Example.COM", "foo.example.com", true},
		{"api.example.com.", "api.example.com", true},
		{"api.example.com", "api.example.com.", true},
	}
	for _, tt := range tests {
		t.Run(tt.pattern+"_vs_"+tt.host, func(t *testing.T) {
			if got := MatchHost(tt.pattern, tt.host); got != tt.want {
				t.Errorf("MatchHost(%q, %q) = %v, want %v", tt.pattern, tt.host, got, tt.want)
			}
		})
	}
}

func TestLoadDefault(t *testing.T) {
	cfg := LoadDefault()
	if cfg.Version != CurrentVersion || cfg.Tier != TierStrict || len(cfg.AllowPorts) != 2 {
		t.Errorf("unexpected defaults: %+v", cfg)
	}
}
