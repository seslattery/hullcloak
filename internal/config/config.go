package config

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const CurrentVersion = 1

type Tier string

const (
	TierStrict     Tier = "strict"
	TierPermissive Tier = "permissive"
)

type Config struct {
	Version          int      `yaml:"version"`
	Tier             Tier     `yaml:"tier"`
	Allow            []string `yaml:"allow"`
	AllowPorts       []int    `yaml:"allow_ports,omitempty"`
	AllowRead        []string `yaml:"allow_read,omitempty"`
	AllowWrite       []string `yaml:"allow_write,omitempty"`
	AllowUnixSockets []string `yaml:"allow_unix_sockets,omitempty"`
	EnvPassthrough   []string `yaml:"env_passthrough,omitempty"`
}

var defaultAllowPorts = []int{443, 80}

func Load(path string) (*Config, error) {
	expanded, err := expandTilde(path)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(expanded)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg.applyDefaults()
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if err := cfg.normalize(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func LoadDefault() *Config {
	return &Config{
		Version:    CurrentVersion,
		Tier:       TierStrict,
		AllowPorts: append([]int(nil), defaultAllowPorts...),
	}
}

func (c *Config) applyDefaults() {
	if c.Tier == "" {
		c.Tier = TierStrict
	}
	if c.AllowPorts == nil {
		c.AllowPorts = append([]int(nil), defaultAllowPorts...)
	}
}

func (c *Config) normalize() error {
	for i, h := range c.Allow {
		c.Allow[i] = normalizeHost(h)
	}
	c.Allow = dedup(c.Allow)

	var err error
	if c.AllowRead, err = expandTildePaths(c.AllowRead); err != nil {
		return err
	}
	if c.AllowWrite, err = expandTildePaths(c.AllowWrite); err != nil {
		return err
	}
	if c.AllowUnixSockets, err = expandTildePaths(c.AllowUnixSockets); err != nil {
		return err
	}
	c.EnvPassthrough = dedup(c.EnvPassthrough)
	return nil
}

func (c *Config) validate() error {
	if c.Version == 0 {
		return fmt.Errorf("version is required")
	}
	if c.Version != CurrentVersion {
		return fmt.Errorf("unsupported config version: %d (expected %d)", c.Version, CurrentVersion)
	}

	switch c.Tier {
	case TierStrict, TierPermissive:
	default:
		return fmt.Errorf("unknown tier: %q (valid: strict, permissive)", c.Tier)
	}

	if len(c.Allow) == 0 {
		return fmt.Errorf("allow list is required and must not be empty")
	}
	for _, h := range c.Allow {
		if err := validateHost(h); err != nil {
			return fmt.Errorf("invalid allow entry %q: %w", h, err)
		}
	}

	if err := validatePaths(c.AllowRead, "allow_read"); err != nil {
		return err
	}
	if err := validatePaths(c.AllowWrite, "allow_write"); err != nil {
		return err
	}

	if len(c.AllowUnixSockets) > 0 && c.Tier == TierStrict {
		return fmt.Errorf("allow_unix_sockets is only valid in permissive tier")
	}
	if err := validatePaths(c.AllowUnixSockets, "allow_unix_sockets"); err != nil {
		return err
	}

	for _, port := range c.AllowPorts {
		if port < 1 || port > 65535 {
			return fmt.Errorf("allow_ports: %d is not a valid port (must be 1-65535)", port)
		}
	}

	for _, v := range c.EnvPassthrough {
		if !isEnvName(v) {
			return fmt.Errorf("env_passthrough: invalid variable name %q", v)
		}
	}

	return nil
}

func validateHost(raw string) error {
	if raw == "" {
		return fmt.Errorf("empty hostname")
	}
	if strings.ContainsAny(raw, " \t\n\r[]") {
		return fmt.Errorf("contains invalid characters")
	}
	if strings.Contains(raw, "://") {
		return fmt.Errorf("must be a hostname, not a URL")
	}
	if strings.Contains(raw, ":") {
		return fmt.Errorf("must be a hostname without port; use allow_ports for port control")
	}

	h := normalizeHost(raw)

	wildcard := strings.HasPrefix(h, "*.")
	actual := strings.TrimPrefix(h, "*.")

	if strings.Contains(h, "*") && !wildcard {
		return fmt.Errorf("wildcard must be leftmost label (e.g., *.example.com)")
	}
	if strings.Count(h, "*") > 1 {
		return fmt.Errorf("only one wildcard is allowed")
	}

	if net.ParseIP(actual) != nil {
		return fmt.Errorf("IP literals are not supported; use hostnames")
	}
	if !isDomainName(actual) {
		return fmt.Errorf("not a valid hostname")
	}
	if !strings.Contains(actual, ".") {
		if wildcard {
			return fmt.Errorf("wildcard must match at least a second-level domain (e.g., *.example.com)")
		}
		return fmt.Errorf("hostname must contain at least two labels (e.g., example.com)")
	}

	return nil
}

func isDomainName(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		n := len(label)
		if n == 0 || n > 63 {
			return false
		}
		for i, c := range label {
			if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || (c == '-' && i > 0 && i < n-1)) {
				return false
			}
		}
	}
	return true
}

func normalizeHost(h string) string {
	return strings.TrimSuffix(strings.ToLower(h), ".")
}

func validatePaths(paths []string, field string) error {
	for _, p := range paths {
		if p == "" {
			return fmt.Errorf("%s: empty path", field)
		}
		if p == "~" || strings.HasPrefix(p, "~/") {
			continue
		}
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s path must be absolute (or ~ prefixed): %q", field, p)
		}
	}
	return nil
}

func isEnvName(s string) bool {
	if len(s) == 0 {
		return false
	}
	for i, c := range s {
		if c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
			continue
		}
		if i > 0 && c >= '0' && c <= '9' {
			continue
		}
		return false
	}
	return true
}

func expandTilde(path string) (string, error) {
	if path == "~" || strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot expand ~ in path %q: %w", path, err)
		}
		return filepath.Join(home, path[1:]), nil
	}
	return path, nil
}

func expandTildePaths(paths []string) ([]string, error) {
	for i, p := range paths {
		expanded, err := expandTilde(p)
		if err != nil {
			return nil, err
		}
		paths[i] = expanded
	}
	return dedup(paths), nil
}

func dedup(items []string) []string {
	if len(items) == 0 {
		return items
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func MatchHost(pattern, host string) bool {
	pattern = normalizeHost(pattern)
	host = normalizeHost(host)

	if !strings.HasPrefix(pattern, "*.") {
		return pattern == host
	}

	suffix := pattern[1:]
	if !strings.HasSuffix(host, suffix) {
		return false
	}
	prefix := host[:len(host)-len(suffix)]
	return len(prefix) > 0 && !strings.Contains(prefix, ".")
}
