package sandbox

import (
	"fmt"
	"strings"
	"testing"

	"github.com/seslattery/hullcloak/internal/config"
)

func baseParams() *Params {
	return &Params{
		Tier:      config.TierStrict,
		CWD:       "/Users/testuser/project",
		HomeDir:   "/Users/testuser",
		ProxyPort: 49152,
	}
}

func TestGenerateValidation(t *testing.T) {
	tests := []struct {
		name   string
		modify func(*Params)
		substr string
	}{
		{"empty CWD", func(p *Params) { p.CWD = "" }, "CWD is required"},
		{"port zero", func(p *Params) { p.ProxyPort = 0 }, "invalid proxy port"},
		{"port too high", func(p *Params) { p.ProxyPort = 70000 }, "invalid proxy port"},
		{"relative CWD", func(p *Params) { p.CWD = "relative/path" }, "path must be absolute"},
		{"relative AllowRead", func(p *Params) { p.AllowRead = []string{"foo"} }, "path must be absolute"},
		{"null in path", func(p *Params) { p.AllowWrite = []string{"/tmp/\x00bad"} }, "control characters"},
		{"newline in path", func(p *Params) { p.AllowUnixSockets = []string{"/tmp/\nbad"} }, "control characters"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := baseParams()
			tt.modify(p)
			_, err := Generate(p)
			if err == nil || !strings.Contains(err.Error(), tt.substr) {
				t.Errorf("got err=%v, want containing %q", err, tt.substr)
			}
		})
	}
}

func TestStrictTierProfile(t *testing.T) {
	p := baseParams()
	p.AllowRead = []string{"/usr/local/share"}
	p.AllowWrite = []string{"/opt/output"}

	profile, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}

	mustContain := []string{
		"(version 1)",
		"HULLCLOAK_SANDBOX_VIOLATION",
		"(allow process-exec*)",
		"(allow process-fork)",
		"(allow signal (target same-sandbox))",
		"(deny file-read*)\n",
		`(allow file-read* (subpath "/usr"))`,
		`(allow file-read* (subpath "/private/var/db"))`,
		`(allow file-read* (subpath "/private/var/folders"))`,
		`(allow file-read* (subpath "/Users/testuser/project"))`,
		`(allow file-read* (subpath "/usr/local/share"))`,
		`(allow file-read* (subpath "/opt/output"))`,
		`(allow file-read* (literal "/Users/testuser"))`,
		`(allow file-read* (literal "/Users"))`,
		`(deny file-read* (regex #"^/Users/testuser/\..*"))`,
		`(deny file-read* (subpath "/var/run"))`,
		"(deny file-write*)\n",
		`(allow file-write* (subpath "/Users/testuser/project"))`,
		`(allow file-write* (subpath "/tmp"))`,
		`(allow file-write* (subpath "/private/tmp"))`,
		`(allow file-write* (subpath "/private/var/folders"))`,
		`(allow file-write* (subpath "/opt/output"))`,
		`(allow file-write-unlink (subpath "/opt/output"))`,
		`(deny file-write* (regex #"^/Users/testuser/\..*"))`,
		`(deny file-write* (subpath "/var/run"))`,
		"(deny network*)",
		`(allow network-outbound (remote tcp "localhost:49152"))`,
		`(allow network-inbound (local tcp "localhost:*"))`,
		"(allow pseudo-tty)",
		`(allow file-read* (literal "/dev/ptmx"))`,
		`(global-name "com.apple.trustd.agent")`,
		`(global-name "com.apple.securityd.xpc")`,
		"(allow ipc-posix-shm)",
		"(allow sysctl-read)",
		`(allow sysctl-write (sysctl-name "kern.tcsm_enable"))`,
		`(allow file-read* (literal "/dev/random"))`,
		`(literal "/dev/dtracehelper")`,
		`(literal "/bin/ps")`,
		"(with no-sandbox)",
	}

	mustNotContain := []string{
		`(subpath "/var")`,
		`(subpath "/private/var")`,
		"com.apple.accountsd",
		"com.apple.sysmond",
		`(allow network-outbound (remote udp "*:53"))`,
		"/var/run/mDNSResponder",
	}

	for _, want := range mustContain {
		if !strings.Contains(profile, want) {
			t.Errorf("strict profile missing: %s", want)
		}
	}
	for _, nope := range mustNotContain {
		if strings.Contains(profile, nope) {
			t.Errorf("strict profile should not contain: %s", nope)
		}
	}
}

func TestPermissiveTierProfile(t *testing.T) {
	p := baseParams()
	p.Tier = config.TierPermissive
	p.AllowWrite = []string{"/opt/output"}
	p.AllowUnixSockets = []string{"/var/run/docker.sock"}

	profile, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}

	mustContain := []string{
		"(allow file-read*)\n",
		`(deny file-read* (regex #"^/Users/testuser/\..*"))`,
		`(deny file-read* (subpath "/var/run"))`,
		"(deny file-write*)",
		`(allow file-write* (subpath "/Users/testuser/project"))`,
		`(allow file-write* (subpath "/private/tmp"))`,
		`(allow file-write* (subpath "/opt/output"))`,
		`(deny file-write* (regex #"^/Users/testuser/\..*"))`,
		`(allow network-outbound (remote unix-socket (path-literal "/var/run/docker.sock")))`,
		`(allow file-read* (literal "/var/run/docker.sock"))`,
		`(allow file-write* (literal "/var/run/docker.sock"))`,
		`(allow file-ioctl (literal "/var/run/docker.sock"))`,
		`(global-name "com.apple.trustd.agent")`,
		`(global-name "com.apple.accountsd")`,
		`(global-name "com.apple.sysmond")`,
		`(allow network-outbound (remote tcp "localhost:49152"))`,
	}

	mustNotContain := []string{
		`(allow network-outbound (remote udp "*:53"))`,
		"/var/run/mDNSResponder",
	}

	for _, want := range mustContain {
		if !strings.Contains(profile, want) {
			t.Errorf("permissive profile missing: %s", want)
		}
	}
	for _, nope := range mustNotContain {
		if strings.Contains(profile, nope) {
			t.Errorf("permissive profile should not contain: %s", nope)
		}
	}
}

func TestRuleOrdering(t *testing.T) {
	t.Run("strict: dotfile deny after read allows", func(t *testing.T) {
		p := baseParams()
		profile, _ := Generate(p)

		allowCWD := strings.Index(profile, `(allow file-read* (subpath "/Users/testuser/project"))`)
		denyDotfiles := strings.Index(profile, `(deny file-read* (regex #"^/Users/testuser/\..*"))`)

		if allowCWD < 0 || denyDotfiles < 0 {
			t.Fatal("missing expected rules")
		}
		if denyDotfiles <= allowCWD {
			t.Error("dotfile deny must come after CWD allow (last-match-wins)")
		}
	})

	t.Run("permissive: /var/run deny after allow-all reads", func(t *testing.T) {
		p := baseParams()
		p.Tier = config.TierPermissive
		profile, _ := Generate(p)

		allowAll := strings.Index(profile, "(allow file-read*)\n")
		denyVarRun := strings.Index(profile, `(deny file-read* (subpath "/var/run"))`)

		if allowAll < 0 || denyVarRun < 0 {
			t.Fatal("missing expected rules")
		}
		if denyVarRun <= allowAll {
			t.Error("/var/run deny must come after allow-all reads")
		}
	})

	t.Run("permissive: dotfile denies after allow-all reads", func(t *testing.T) {
		p := baseParams()
		p.Tier = config.TierPermissive
		profile, _ := Generate(p)

		allowAll := strings.Index(profile, "(allow file-read*)\n")
		denyDotfiles := strings.Index(profile, `(deny file-read* (regex #"^/Users/testuser/\..*"))`)
		if allowAll < 0 || denyDotfiles < 0 {
			t.Fatal("missing expected permissive dotfile rules")
		}
		if denyDotfiles <= allowAll {
			t.Error("permissive dotfile deny must come after allow-all reads")
		}
	})

	t.Run("strict: write dotfile deny after write allows", func(t *testing.T) {
		p := baseParams()
		profile, _ := Generate(p)

		allowCWDWrite := strings.Index(profile, `(allow file-write* (subpath "/Users/testuser/project"))`)
		denyDotfileWrite := strings.Index(profile, `(deny file-write* (regex #"^/Users/testuser/\..*"))`)

		if allowCWDWrite < 0 || denyDotfileWrite < 0 {
			t.Fatal("missing expected write rules")
		}
		if denyDotfileWrite <= allowCWDWrite {
			t.Error("dotfile write deny must come after CWD write allow")
		}
	})

	t.Run("permissive: unix socket allows after /var/run deny", func(t *testing.T) {
		p := baseParams()
		p.Tier = config.TierPermissive
		p.AllowUnixSockets = []string{"/var/run/docker.sock"}
		profile, _ := Generate(p)

		denyVarRun := strings.Index(profile, `(deny file-read* (subpath "/var/run"))`)
		sockAllow := strings.Index(profile, `(allow network-outbound (remote unix-socket (path-literal "/var/run/docker.sock")))`)

		if denyVarRun < 0 || sockAllow < 0 {
			t.Fatal("missing expected rules")
		}
		if sockAllow <= denyVarRun {
			t.Error("unix socket allow must come after /var/run deny")
		}
	})
}

func TestStrictNoUnixSockets(t *testing.T) {
	p := baseParams()
	p.AllowUnixSockets = []string{"/var/run/docker.sock"}

	profile, err := Generate(p)
	if err != nil {
		t.Fatal(err)
	}

	if strings.Contains(profile, "Unix socket exceptions") {
		t.Error("strict tier should not emit unix socket section")
	}
	// Strict tier ignores user-provided unix socket exceptions, but the base
	// profile still includes mDNSResponder's AF_UNIX socket for DNS resolution.
	if strings.Contains(profile, "/var/run/docker.sock") {
		t.Error("strict tier should not emit user-provided unix socket rules")
	}
}

func TestProxyPortInProfile(t *testing.T) {
	for _, port := range []int{1234, 49152, 65535} {
		p := baseParams()
		p.ProxyPort = port

		profile, err := Generate(p)
		if err != nil {
			t.Fatal(err)
		}

		want := fmt.Sprintf(`(allow network-outbound (remote tcp "localhost:%d"))`, port)
		if !strings.Contains(profile, want) {
			t.Errorf("port %d: missing %s", port, want)
		}
	}
}

func TestSbplQuote(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/simple/path", "/simple/path"},
		{`path with "quotes"`, `path with \"quotes\"`},
		{`back\slash`, `back\\slash`},
	}
	for _, tt := range tests {
		if got := sbplQuote(tt.in); got != tt.want {
			t.Errorf("sbplQuote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestRegexQuote(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/Users/sean", "/Users/sean"},
		{"/Users/j.doe", `/Users/j\.doe`},
		{"/path+special", `/path\+special`},
		{"/a(b)c", `/a\(b\)c`},
	}
	for _, tt := range tests {
		if got := regexQuote(tt.in); got != tt.want {
			t.Errorf("regexQuote(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestSystemReadPaths(t *testing.T) {
	paths := systemReadPaths()
	required := []string{"/usr", "/bin", "/sbin", "/opt", "/etc", "/private/etc",
		"/System", "/Applications", "/Library", "/dev", "/tmp", "/private/tmp",
		"/nix", "/private/var/db", "/private/var/folders"}

	pathSet := make(map[string]bool, len(paths))
	for _, p := range paths {
		pathSet[p] = true
	}

	for _, r := range required {
		if !pathSet[r] {
			t.Errorf("missing system path: %s", r)
		}
	}

	forbidden := []string{"/var", "/private/var", "/Users"}
	for _, f := range forbidden {
		if pathSet[f] {
			t.Errorf("should not include: %s", f)
		}
	}
}

func TestMachServicesForTier(t *testing.T) {
	strict := machServicesForTier(config.TierStrict)
	permissive := machServicesForTier(config.TierPermissive)

	if len(permissive) <= len(strict) {
		t.Error("permissive should have more mach services than strict")
	}

	has := func(list []string, s string) bool {
		for _, v := range list {
			if v == s {
				return true
			}
		}
		return false
	}

	for _, svc := range []string{"com.apple.trustd.agent", "com.apple.securityd.xpc", "com.apple.SystemConfiguration.configd"} {
		if !has(strict, svc) {
			t.Errorf("strict missing TLS-critical service: %s", svc)
		}
	}

	for _, svc := range []string{"com.apple.accountsd", "com.apple.sysmond"} {
		if has(strict, svc) {
			t.Errorf("strict should not have: %s", svc)
		}
		if !has(permissive, svc) {
			t.Errorf("permissive missing: %s", svc)
		}
	}
}

func TestNoSandboxEscape(t *testing.T) {
	for _, tier := range []config.Tier{config.TierStrict, config.TierPermissive} {
		p := baseParams()
		p.Tier = tier
		profile, _ := Generate(p)

		count := strings.Count(profile, "no-sandbox")
		if count != 1 {
			t.Errorf("%s: expected exactly 1 no-sandbox (for /bin/ps), got %d", tier, count)
		}
		if !strings.Contains(profile, `(literal "/bin/ps")`) {
			t.Errorf("%s: no-sandbox must be scoped to /bin/ps", tier)
		}
	}
}

func TestWriteTargetsIncludesPrivateTmp(t *testing.T) {
	targets := writeTargets("/project", nil)
	found := false
	for _, tgt := range targets {
		if tgt == "/private/tmp" {
			found = true
			break
		}
	}
	if !found {
		t.Error("writeTargets should include /private/tmp because /tmp resolves to it on macOS")
	}
}

func TestDotfileExceptions(t *testing.T) {
	t.Run("no dotfiles in allow lists emits simple deny", func(t *testing.T) {
		p := baseParams()
		p.AllowRead = []string{"/usr/local/share"}
		profile, _ := Generate(p)

		if strings.Contains(profile, "require-not") {
			t.Error("no dotfile paths should not emit require-not")
		}
		if !strings.Contains(profile, `(deny file-read* (regex #"^/Users/testuser/\..*"))`) {
			t.Error("missing simple dotfile deny")
		}
	})

	t.Run("dotfile in allow_read creates exception", func(t *testing.T) {
		p := baseParams()
		p.AllowRead = []string{"/Users/testuser/.claude.json"}
		profile, _ := Generate(p)

		mustContain := []string{
			"require-all",
			`(require-not (literal "/Users/testuser/.claude.json"))`,
			`(require-not (subpath "/Users/testuser/.claude.json"))`,
			`(regex #"^/Users/testuser/\..*")`,
		}
		for _, want := range mustContain {
			if !strings.Contains(profile, want) {
				t.Errorf("missing: %s", want)
			}
		}

		readDeny := strings.Index(profile, "(deny file-read*\n  (require-all")
		writeDeny := strings.Index(profile, "(deny file-write*\n  (require-all")
		if readDeny < 0 {
			t.Error("read deny should use require-all with exceptions")
		}
		if writeDeny < 0 {
			t.Error("write deny should use require-all with exceptions")
		}
	})

	t.Run("dotfile in allow_write creates exception", func(t *testing.T) {
		p := baseParams()
		p.AllowWrite = []string{"/Users/testuser/.config"}
		profile, _ := Generate(p)

		if !strings.Contains(profile, `(require-not (literal "/Users/testuser/.config"))`) {
			t.Error("dotfile in allow_write should create exception")
		}
		if !strings.Contains(profile, `(require-not (subpath "/Users/testuser/.config"))`) {
			t.Error("dotfile in allow_write should create subpath exception")
		}
	})

	t.Run("dotfile directory exception uses subpath for descendants", func(t *testing.T) {
		p := baseParams()
		p.AllowRead = []string{"/Users/testuser/.claude"}
		profile, _ := Generate(p)

		if !strings.Contains(profile, `(require-not (subpath "/Users/testuser/.claude"))`) {
			t.Error("dotfile directory exception should use subpath to cover descendants")
		}
	})

	t.Run("non-dotfile paths do not create exceptions", func(t *testing.T) {
		p := baseParams()
		p.AllowRead = []string{"/Users/testuser/project"}
		profile, _ := Generate(p)

		if strings.Contains(profile, "require-not") {
			t.Error("non-dotfile path should not create exception")
		}
	})

	t.Run("deduplicates across allow_read and allow_write", func(t *testing.T) {
		p := baseParams()
		p.AllowRead = []string{"/Users/testuser/.claude.json"}
		p.AllowWrite = []string{"/Users/testuser/.claude.json"}
		profile, _ := Generate(p)

		count := strings.Count(profile, `(require-not (literal "/Users/testuser/.claude.json"))`)
		// 2 occurrences expected: one in read deny, one in write deny
		if count != 2 {
			t.Errorf("expected 2 require-not (read+write), got %d", count)
		}
	})
}

func TestAncestors(t *testing.T) {
	tests := []struct {
		name  string
		paths []string
		want  []string
	}{
		{"single path", []string{"/Users/sean/dev/project"}, []string{"/Users/sean/dev", "/Users/sean", "/Users"}},
		{"root child", []string{"/usr"}, nil},
		{"overlapping", []string{"/a/b/c", "/a/b/d"}, []string{"/a/b", "/a"}},
		{"dedup", []string{"/a/b/c", "/a/b/c"}, []string{"/a/b", "/a"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ancestors(tt.paths)
			if len(got) != len(tt.want) {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d]=%q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestHomeDotfiles(t *testing.T) {
	tests := []struct {
		name  string
		home  string
		paths [][]string
		want  []string
	}{
		{"no dotfiles", "/Users/test", [][]string{{"/usr/local"}}, nil},
		{"dotfile match", "/Users/test", [][]string{{"/Users/test/.ssh"}}, []string{"/Users/test/.ssh"}},
		{"non-home dotfile ignored", "/Users/test", [][]string{{"/other/.ssh"}}, nil},
		{"dedup", "/Users/test", [][]string{{"/Users/test/.ssh"}, {"/Users/test/.ssh"}}, []string{"/Users/test/.ssh"}},
		{"multiple", "/Users/test", [][]string{{"/Users/test/.ssh", "/Users/test/.config"}}, []string{"/Users/test/.ssh", "/Users/test/.config"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := homeDotfiles(tt.home, tt.paths...)
			if len(got) != len(tt.want) {
				t.Errorf("got %v, want %v", got, tt.want)
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d]=%q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}
