package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/seslattery/hullcloak/internal/config"
)

// Params holds inputs for sandbox profile generation.
type Params struct {
	Tier             config.Tier
	CWD              string
	HomeDir          string
	ProxyPort        int
	AllowRead        []string
	AllowWrite       []string
	AllowUnixSockets []string
}

// Generate produces an SBPL sandbox profile from the given params.
func Generate(p *Params) (string, error) {
	if p.CWD == "" {
		return "", fmt.Errorf("CWD is required")
	}
	if p.HomeDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("cannot determine home directory: %w", err)
		}
		p.HomeDir = home
	}
	if p.ProxyPort < 1 || p.ProxyPort > 65535 {
		return "", fmt.Errorf("invalid proxy port: %d", p.ProxyPort)
	}
	if err := validatePaths("CWD", []string{p.CWD}); err != nil {
		return "", err
	}
	if err := validatePaths("HomeDir", []string{p.HomeDir}); err != nil {
		return "", err
	}
	if err := validatePaths("AllowRead", p.AllowRead); err != nil {
		return "", err
	}
	if err := validatePaths("AllowWrite", p.AllowWrite); err != nil {
		return "", err
	}
	if err := validatePaths("AllowUnixSockets", p.AllowUnixSockets); err != nil {
		return "", err
	}

	dotfileExceptions := homeDotfiles(p.HomeDir, p.AllowRead, p.AllowWrite)

	var b strings.Builder
	b.Grow(4096)

	w := func(s string) { b.WriteString(s) }
	wf := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }
	homeRe := regexQuote(p.HomeDir)
	varRunPaths := []string{"/var/run", "/private/var/run"}
	devWrite := []string{"/dev/null", "/dev/zero", "/dev/tty", "/dev/dtracehelper"}
	devAll := []string{"/dev/null", "/dev/zero", "/dev/tty", "/dev/random", "/dev/urandom", "/dev/dtracehelper"}

	w("(version 1)\n")
	w("(deny default (with message \"HULLCLOAK_SANDBOX_VIOLATION\"))\n\n")

	// Process
	w(";; Process\n")
	w("(allow process-exec*)\n")
	w("(allow process-fork)\n")
	w("(allow signal (target same-sandbox))\n")
	w("(allow process-info* (target same-sandbox))\n")
	w("(allow mach-priv-task-port (target same-sandbox))\n")
	w("(allow process-exec-interpreter)\n")
	w("(allow process-exec\n")
	w("  (literal \"/bin/ps\")\n")
	w("  (with no-sandbox))\n\n")

	// Filesystem reads — SBPL is last-match-wins: allows first, denies last.
	if p.Tier == config.TierStrict {
		w(";; Strict: deny reads, allow system paths\n")
		w("(deny file-read*)\n")
		w("(allow file-read* (literal \"/\"))\n")
		emitSubpath(&b, "allow", "file-read*", systemReadPaths())
		allReadPaths := append([]string{p.CWD}, p.AllowRead...)
		allReadPaths = append(allReadPaths, p.AllowWrite...)
		emitSubpath(&b, "allow", "file-read*", allReadPaths)
		emitLiteral(&b, "file-read*", ancestors(allReadPaths))
	} else {
		w(";; Permissive: allow reads\n")
		w("(allow file-read*)\n")
	}

	// Read denies after allows (socket exceptions may follow in permissive)
	w("\n;; Read denies (after allows for last-match-wins)\n")
	emitDotfileDeny(&b, "file-read*", homeRe, dotfileExceptions)
	emitSubpath(&b, "deny", "file-read*", varRunPaths)
	w("\n")

	// Writes
	w(";; Writes\n")
	w("(deny file-write*)\n")
	for _, path := range writeTargets(p.CWD, p.AllowWrite) {
		qp := sbplQuote(path)
		wf("(allow file-write* (subpath \"%s\"))\n", qp)
		wf("(allow file-write-unlink (subpath \"%s\"))\n", qp)
	}

	// Write denies after allows
	w("\n;; Write denies\n")
	emitDotfileDeny(&b, "file-write*", homeRe, dotfileExceptions)
	emitSubpath(&b, "deny", "file-write*", varRunPaths)
	w("\n")

	// Devices
	w(";; Devices\n")
	emitLiteral(&b, "file-write*", devWrite)
	emitLiteral(&b, "file-ioctl", devAll)
	if p.Tier == config.TierStrict {
		emitLiteral(&b, "file-read*", devAll)
	}
	w("\n")

	// Network
	w(";; Network\n")
	w("(deny network*)\n")
	// Localhost proxy access (TCP)
	w("(allow network-bind (local ip \"localhost:*\"))\n")
	wf("(allow network-outbound (remote tcp \"localhost:%d\"))\n", p.ProxyPort)
	w("(allow network-inbound (local tcp \"localhost:*\"))\n")

	// Unix socket exceptions (permissive only, after /var/run denies)
	if len(p.AllowUnixSockets) > 0 && p.Tier == config.TierPermissive {
		w("\n;; Unix socket exceptions\n")
		for _, sock := range p.AllowUnixSockets {
			qs := sbplQuote(sock)
			wf("(allow network-outbound (remote unix-socket (path-literal \"%s\")))\n", qs)
			wf("(allow file-read* (literal \"%s\"))\n", qs)
			wf("(allow file-write* (literal \"%s\"))\n", qs)
			wf("(allow file-ioctl (literal \"%s\"))\n", qs)
		}
	}
	w("\n")

	// PTY
	w(";; PTY\n")
	w("(allow pseudo-tty)\n")
	for _, op := range []string{"file-read*", "file-write*", "file-ioctl"} {
		wf("(allow %s (literal \"/dev/ptmx\"))\n", op)
		wf("(allow %s (regex #\"^/dev/ttys[0-9]+$\"))\n", op)
	}
	w("\n")

	// Mach services
	w(";; Mach services\n")
	w("(allow mach-lookup\n")
	for _, svc := range machServicesForTier(p.Tier) {
		wf("  (global-name \"%s\")\n", svc)
	}
	w(")\n\n")

	// System compatibility
	w(";; System compatibility\n")
	w("(allow ipc-posix-shm)\n")
	w("(allow ipc-posix-sem)\n")
	w("(allow user-preference-read)\n")
	w("(allow sysctl-read)\n")
	w("(allow sysctl-write (sysctl-name \"kern.tcsm_enable\"))\n")
	w("(allow iokit-get-properties)\n")
	w("(allow iokit-open\n")
	w("  (iokit-registry-entry-class \"IOSurfaceRootUserClient\")\n")
	w("  (iokit-registry-entry-class \"RootDomainUserClient\")\n")
	w("  (iokit-user-client-class \"IOSurfaceSendRight\"))\n")
	w("(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))\n")
	w("(allow distributed-notification-post)\n")

	return b.String(), nil
}

func validatePaths(field string, paths []string) error {
	for _, p := range paths {
		if !filepath.IsAbs(p) {
			return fmt.Errorf("%s: path must be absolute: %q", field, p)
		}
		if strings.ContainsAny(p, "\x00\r\n") {
			return fmt.Errorf("%s: path contains control characters: %q", field, p)
		}
	}
	return nil
}

func homeDotfiles(home string, pathLists ...[]string) []string {
	prefix := home + "/."
	seen := map[string]struct{}{}
	var out []string
	for _, paths := range pathLists {
		for _, p := range paths {
			if strings.HasPrefix(p, prefix) {
				if _, ok := seen[p]; !ok {
					seen[p] = struct{}{}
					out = append(out, p)
				}
			}
		}
	}
	return out
}

func emitDotfileDeny(b *strings.Builder, op, homeRe string, exceptions []string) {
	if len(exceptions) == 0 {
		fmt.Fprintf(b, "(deny %s (regex #\"^%s/\\..*\"))\n", op, homeRe)
		return
	}
	fmt.Fprintf(b, "(deny %s\n  (require-all\n    (regex #\"^%s/\\..*\")\n", op, homeRe)
	for _, exc := range exceptions {
		fmt.Fprintf(b, "    (require-not (literal \"%s\"))\n", sbplQuote(exc))
		fmt.Fprintf(b, "    (require-not (subpath \"%s\"))\n", sbplQuote(exc))
	}
	fmt.Fprintf(b, "  ))\n")
}

func emitSubpath(b *strings.Builder, action, op string, paths []string) {
	for _, p := range paths {
		fmt.Fprintf(b, "(%s %s (subpath \"%s\"))\n", action, op, sbplQuote(p))
	}
}

func emitLiteral(b *strings.Builder, op string, paths []string) {
	for _, p := range paths {
		fmt.Fprintf(b, "(allow %s (literal \"%s\"))\n", op, sbplQuote(p))
	}
}

func sbplQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}

func regexQuote(s string) string {
	const meta = `\.+*?^${}()|[]`
	var b strings.Builder
	b.Grow(len(s))
	for _, c := range s {
		if strings.ContainsRune(meta, c) {
			b.WriteByte('\\')
		}
		b.WriteRune(c)
	}
	return b.String()
}

func systemReadPaths() []string {
	return []string{
		"/usr", "/bin", "/sbin", "/opt",
		"/etc", "/private/etc",
		"/System", "/Applications", "/Library",
		"/dev", "/tmp", "/private/tmp",
		"/nix",
		"/private/var/db",
		"/private/var/folders",
	}
}

func writeTargets(cwd string, extra []string) []string {
	// On macOS, /tmp resolves to /private/tmp; include both so writes work
	// regardless of whether a process uses the symlink or resolved path.
	targets := []string{cwd, "/tmp", "/private/tmp", "/private/var/folders"}
	return append(targets, extra...)
}

func ancestors(paths []string) []string {
	seen := map[string]struct{}{"/": {}}
	var out []string
	for _, p := range paths {
		for d := filepath.Dir(p); d != "/" && d != "."; d = filepath.Dir(d) {
			if _, ok := seen[d]; ok {
				break
			}
			seen[d] = struct{}{}
			out = append(out, d)
		}
	}
	return out
}

func machServicesForTier(tier config.Tier) []string {
	base := []string{
		"com.apple.system.opendirectoryd.libinfo",
		"com.apple.system.opendirectoryd.membership",
		"com.apple.system.logger",
		"com.apple.system.notification_center",
		"com.apple.bsd.dirhelper",
		"com.apple.logd",
		"com.apple.lsd.mapdb",
		"com.apple.coreservices.launchservicesd",
		"com.apple.distributed_notifications@Uv3",
		"com.apple.fonts",
		"com.apple.FontObjectsServer",
		"com.apple.securityd.xpc",
		"com.apple.trustd.agent",
		"com.apple.SecurityServer",
		"com.apple.security.agent",
		"com.apple.CoreAuthentication.agent",
		"com.apple.PowerManagement.control",
		"com.apple.SystemConfiguration.DNSConfiguration",
		"com.apple.SystemConfiguration.configd",
		"com.apple.analyticsd",
		"com.apple.FSEvents",                           // File system watching (used by Node.js/libuv)
		"com.apple.dnssd.service",                      // DNS Service Discovery (Bonjour/mDNS)
		"com.apple.system.DirectoryService.libinfo_v1", // Directory services for DNS
	}
	if tier == config.TierPermissive {
		base = append(base,
			"com.apple.cfnetwork.AuthBrokerAgent",
			"com.apple.accountsd",
			"com.apple.audio.systemsoundserver",
			"com.apple.sysmond",
		)
	}
	return base
}
