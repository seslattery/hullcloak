# Hullcloak Design

Binary: `hc` | macOS only (v1) | Go 1.21+

## What It Is

A minimal process sandbox + allowlist proxy for wrapping AI coding agents (Claude, Amp, Codex) on macOS. No secret injection, no OPA, no Doppler. Seatbelt sandboxing + goproxy host+port allowlisting + blocked-request logging.

## Threat Model

Prevent AI agents from:

- Reading sensitive files (~/.ssh, ~/.aws, ~/.config, dotfiles, Keychain)
- Writing outside the project directory
- Reaching hosts/ports not explicitly allowed
- Bypassing the proxy via direct TCP/DNS
- Escaping via local unix sockets (Docker, colima, etc.)
- SSRF to private/loopback IPs via DNS rebinding

### Known Limitations (v1)

- **Env stripping uses heuristics.** Strips `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_CREDENTIAL`, `*_AUTH`, `*_PRIVATE` plus known sensitive vars. Secrets with unusual names may slip through. Use `env_passthrough` to explicitly preserve vars agents need for auth.
- **Env stripping protects the child process only.** The hc/proxy process itself still runs with the user's full environment. A proxy RCE would expose it. Sandboxing the proxy process is v2.
- **Permissive tier is not "safe-ish."** It allows reading almost everything outside dotfiles, including `~/Library/Keychains`, browser profiles, app support dirs. Use strict tier for real security; permissive is a compatibility fallback.
- **`sandbox-exec` is deprecated-ish.** Behavior can differ across macOS versions. Use `--dry-run` / `--print-profile` to debug.
- **Git over SSH will fail.** `~/.ssh` is blocked by design. Use HTTPS + token or vendor dependencies.
- **IP literal hosts are not supported in v1.** Allowlist entries and request targets must be hostnames, not IP addresses. Requests to IP literals are rejected.

## CLI

```bash
hc init              # Creates ~/.hullcloak/ with starter config.yaml
hc <command>         # Wraps command in sandbox + proxy
hc claude            # Example: wrap Claude
hc amp chat          # Example: wrap Amp
hc --verbose <cmd>   # Verbose logging
hc --dry-run <cmd>   # Print generated seatbelt profile without executing
hc --print-profile   # Print the SBPL profile and exit
hc clean             # Remove .hullcloak-tmp/ from current directory
```

## Config

Lives at `~/.hullcloak/config.yaml`. Created by `hc init`.

### Minimal config (common case)

```yaml
version: 1

tier: strict

allow:
  - api.anthropic.com
  - api.openai.com
  - "*.githubusercontent.com"
  - api.github.com
  - registry.npmjs.org
```

### With optional overrides

```yaml
version: 1

tier: strict

allow:
  - api.anthropic.com
  - api.openai.com
  - "*.githubusercontent.com"
  - api.github.com
  - registry.npmjs.org

# Override default allowed ports (default: [443, 80])
allow_ports: [443, 80, 8080]

# Extra readable paths beyond system paths (strict tier only)
# Must be absolute paths. Tilde (~) is expanded. Recursive (subpath).
allow_read:
  - /usr/local/share

# Extra writable paths beyond cwd (both tiers)
# Must be absolute paths. Tilde (~) is expanded. Recursive (subpath).
allow_write:
  - /tmp

# Unix sockets to allow (permissive tier only, denied in strict)
allow_unix_sockets:
  - /var/run/docker.sock

# Env vars to preserve despite matching strip patterns (e.g., agent auth)
env_passthrough:
  - ANTHROPIC_API_KEY
  - OPENAI_API_KEY
```

### Config Rules

- `version` is required. Unknown versions are a hard error.
- `allow` with no entries is a hard error in both tiers (nothing would work).
- `allow` entries must be hostnames, not IP addresses. IP literals are rejected.
- `allow` entries with URL schemes (`http://`), whitespace, or empty strings are rejected.
- Duplicate entries are silently deduplicated.
- `allow_read` / `allow_write` must be absolute paths (or `~` prefixed). No relative paths.
- Tilde (`~`) is expanded to `$HOME`.
- All path entries are recursive (seatbelt `subpath` semantics).
- `allow_unix_sockets` is only valid in permissive tier. Specifying it in strict tier is a validation error.
- Wildcard host matching requires a dot boundary: `*.githubusercontent.com` matches `foo.githubusercontent.com` but not `githubusercontent.com` or `githubusercontent.com.evil.com`.
- Hostnames are matched case-insensitively. Trailing dots are stripped.

### Defaults (no config needed)

- Default allowed ports: 443, 80
- System paths always readable (strict tier):
  - /usr, /bin, /sbin, /opt
  - /etc, /private/etc
  - /System, /Applications, /Library
  - /dev, /tmp, /private/tmp
  - /nix
  - /private/var/db (dyld shared cache, etc.)
  - /private/var/folders (per-user temp — writable too)
- Explicitly denied even within allowed trees:
  - /var/run, /private/var/run (docker.sock, colima, containerd, etc.)
  - /var/run/docker.sock, /private/var/run/docker.sock (explicit)
- Working directory always readable + writable (canonicalized via `realpath`)
- /tmp, /private/var/folders always writable
- All ~/.\* dotfiles blocked (both tiers)

**Note:** `/var` and `/private/var` are NOT broadly allowed. Only specific safe subdirectories are permitted.

## Tiers

Two tiers, no more.

### Strict (default)

Deny-all filesystem reads. Only system paths, working directory, and explicit `allow_read` entries are readable. Writes denied everywhere except cwd, /tmp, /private/var/folders, and `allow_write`. No Keychain access, no home directory config files. All unix sockets denied (no override).

### Permissive

Allow-all filesystem reads, except ~/.\* dotfiles (hardcoded deny). Writes denied everywhere except cwd, /tmp, /private/var/folders, and `allow_write`. Unix sockets denied by default, but specific sockets can be allowed via `allow_unix_sockets`. For agents needing broader filesystem access (Docker, complex toolchains).

**Warning:** Permissive tier allows reading ~/Library/Keychains, browser profiles, and other sensitive non-dotfile locations. It is a compatibility fallback, not a security guarantee.

## Proxy

- goproxy (github.com/elazarl/goproxy) as the proxy library
- Host + port allowlisting on both CONNECT requests and plain HTTP proxy requests (`GET http://host/...`)
- Default allowed ports: 443, 80 (configurable via `allow_ports`)
- CONNECT to non-allowed host:port → reject with 403
- Plain HTTP proxy requests → same allowlist check
- Requests to IP literal targets (e.g., `CONNECT 1.2.3.4:443`) → reject (v1 does not support IP-based allowlisting)
- DNS resolution guard: on each outbound dial, resolve host to all IPs, filter out loopback (`127.0.0.0/8`, `::1`), private (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), link-local (`169.254.0.0/16`, `fe80::/10`), ULA (`fc00::/7`), and IPv4-mapped IPv6 (`::ffff:<private>`). Reject if no public IPs remain. No DNS caching — resolve per connection.
- Blocked requests logged to `~/.hullcloak/proxy.log` with timestamp, host, port, and reason
- Proxy log capped at 10MB, rotated on startup (rename to proxy.log.1, overwriting any existing .1 file)
- Proxy binds to localhost on a random available port
- Proxy's outbound transport does NOT inherit HTTP_PROXY/HTTPS_PROXY from environment (uses direct dialer)
- Child process env vars set by hc:
  - `HTTP_PROXY` and `http_proxy` → proxy address
  - `HTTPS_PROXY` and `https_proxy` → proxy address
  - `NO_PROXY` and `no_proxy` → cleared (set to empty string)
  - `ALL_PROXY` and `all_proxy` → cleared (set to empty string)
- Env var stripping (denylist approach):
  1. Start from `os.Environ()`
  2. Remove keys matching suffix patterns (case-insensitive): `*_KEY`, `*_TOKEN`, `*_SECRET`, `*_PASSWORD`, `*_CREDENTIAL`, `*_AUTH`, `*_PRIVATE`
  3. Remove known sensitive vars by exact name (case-insensitive): `AWS_SECRET_ACCESS_KEY`, `GITHUB_TOKEN`, `KUBECONFIG`, `GOOGLE_APPLICATION_CREDENTIALS`, `DOPPLER_TOKEN`, and others
  4. Re-add any vars listed in `env_passthrough` config
  5. Overwrite/add proxy + TMPDIR/XDG_CACHE_HOME vars, then exec
  - Non-secret vars (`PATH`, `HOME`, `USER`, `SHELL`, `EDITOR`, `TERM`, `LANG`, `NODE_ENV`, `GOPATH`, `GOROOT`, etc.) pass through untouched — they don't match any strip pattern
  - `--verbose` logs which vars were stripped (names only, never values)

### Hostname Matching Rules

- Case-insensitive comparison
- Trailing dots stripped (e.g., `example.com.` → `example.com`)
- IPv6 brackets parsed correctly (`[::1]:443`) — but rejected in v1 (IP literals not supported)
- Wildcard `*` only valid as leftmost label: `*.example.com`
- Wildcard requires dot boundary: `*.example.com` matches `foo.example.com` but not `example.com` or `example.com.evil.com`

## Sandbox

- macOS seatbelt (sandbox-exec) only
- SBPL profile generated at runtime from config
- Working directory canonicalized via `realpath` before profile generation (symlink safety)
- Network: deny all, allow only localhost:\<proxy-port\> outbound (port-specific enforcement)
- Localhost inbound allowed on all ports (for dev servers within the sandbox). This means other processes on the host can reach into the sandbox via localhost — acceptable tradeoff for dev server use cases, but documented as a known surface.
- Filesystem: per tier (see above)
- Unix sockets: all AF_UNIX connections denied by default in both tiers. In permissive tier, specific socket paths can be allowed via `allow_unix_sockets` config. In strict tier, no unix socket access is possible.
- PTY support enabled for interactive agents
- Process: allow exec, fork, same-sandbox signals
- Mach services: minimal allowlist required for HTTPS/TLS to work (trustd, securityd, and other essential XPC services — port from veilwarden's proven list)

### Environment Redirection

To improve agent compatibility without widening sandbox permissions, hc sets these env vars pointing to project-local temporary directories:

- `TMPDIR` → `<canonical-cwd>/.hullcloak-tmp/tmp/` (absolute path, trailing slash)
- `XDG_CACHE_HOME` → `<canonical-cwd>/.hullcloak-tmp/cache/`

`XDG_CONFIG_HOME` is intentionally NOT redirected. Config directories are too likely to accumulate tokens, auth caches, and other sensitive state that would then be readable/writable by the agent inside the project tree.

These directories are created on startup with mode `0700`. They persist across runs (not cleaned up on exit) because:
- Tools expect cache/tmp state to survive across sessions
- Concurrent hc runs in the same project won't collide or corrupt
- `hc clean` provides explicit cleanup when wanted

No special `allow_write` entry is needed — `.hullcloak-tmp/` is under cwd, which is already writable.

Users should add `.hullcloak-tmp/` to `.gitignore`. `hc init` prints a reminder to do this.

### Agent Compatibility Notes

- **Claude/Amp/Codex** may store auth/config under `~/.config/` or macOS Keychain. In strict tier, these are blocked by design. Agents must support auth via env vars (listed in `env_passthrough`) or project-local config.
- **No Keychain access** in strict tier. Tools that use macOS Keychain APIs for tokens will fail. This is intentional — accepting the risk of Keychain access contradicts the threat model.
- **Node/Electron apps** may try to write to `~/Library/Caches` or `~/.cache`. The TMPDIR/XDG_CACHE_HOME redirection handles this.
- **Git over SSH** will fail (`~/.ssh` is blocked). Use HTTPS.

## Architecture

```
cmd/hc/
├── main.go          # Entry point
├── root.go          # Root cobra command
├── init.go          # hc init
├── clean.go         # hc clean
└── run.go           # hc <command> (default action)

internal/
├── config/          # YAML loading, defaults, validation
├── env/             # Environment filtering (strip secrets, set proxy vars)
├── proxy/           # goproxy allowlist + blocked request logging
├── sandbox/         # Seatbelt profile generation + exec
└── exec/            # Orchestration: start proxy, build sandbox, run command
```

### Execution flow

1. `hc <command>` parses args, loads ~/.hullcloak/config.yaml, validates
2. Canonicalizes cwd via `realpath`
3. Creates `.hullcloak-tmp/` subdirs in canonical cwd (mode 0700)
4. Starts goproxy on localhost:random with allowlist + DNS guard
5. Builds child environment: strip secret vars, re-add `env_passthrough` vars, set proxy vars + TMPDIR/XDG_CACHE_HOME, clear NO_PROXY/ALL_PROXY
6. Generates seatbelt SBPL profile using canonical cwd + proxy port + tmp paths
7. Runs `sandbox-exec -p <profile> <command>` with filtered environment
8. Waits for child exit, cleans up proxy (tmp dirs persist)

## Implementation Plan

Each step is a standalone, reviewable commit that builds and tests.

### Step 1: Scaffold

- `go mod init`
- Cobra CLI skeleton
- `hc version`
- `hc init` creates `~/.hullcloak/config.yaml` with commented example, prints .gitignore reminder
- `hc clean` removes `.hullcloak-tmp/` from cwd
- No functionality yet

### Step 2: Config

- `internal/config` package
- Load YAML, merge defaults, validate
- Version check (unknown version → hard error)
- Unknown tier → error, empty allow → hard error in both tiers
- Path validation (must be absolute or ~-prefixed)
- Hostname normalization (lowercase, strip trailing dot)
- Reject IP literals, URL schemes, whitespace, empty strings in allow entries
- Wildcard validation (only leftmost label, dot-boundary)
- `allow_unix_sockets` rejected in strict tier
- Deduplicate entries
- Unit tests

### Step 3: Env Filtering

- `internal/env` package
- Strip env vars matching suffix patterns (`*_KEY`, `*_TOKEN`, `*_SECRET`, etc.)
- Strip known sensitive vars by exact name
- Preserve safe vars (PATH, HOME, etc.)
- Set proxy env vars (both cases), clear NO_PROXY/ALL_PROXY
- `--verbose` support: log stripped var names (not values)
- Unit tests

### Step 4: Proxy

- `internal/proxy` package
- goproxy server with host+port allowlist
- Handle both CONNECT and plain HTTP proxy requests
- Reject IP literal targets
- DNS resolution guard: resolve all IPs, filter private/loopback/link-local/ULA (including IPv4-mapped IPv6), reject if no public IPs remain, no DNS caching
- Port restriction (default 443, 80)
- Log blocked requests to proxy.log with rotation (10MB cap, overwrite .1)
- Proxy transport uses direct dialer (no inherited proxy env)
- Unit tests with test HTTP client

### Step 5: Sandbox

- `internal/sandbox` package
- Seatbelt SBPL profile generation for both tiers
- Tightened system paths (no broad /var access)
- Explicit AF_UNIX deny, with per-socket allows for permissive tier
- Mach service allowlist for TLS (port from veilwarden)
- Port-specific localhost network rules (outbound to proxy port only, inbound on all ports)
- Unit tests on generated profiles (string matching, no actual sandbox-exec)

### Step 6: Exec orchestration

- `internal/exec` package
- Wire it all together: canonicalize cwd → create tmp dirs (0700) → start proxy → strip secret env vars → generate profile → set env (proxy + TMPDIR + XDG_CACHE_HOME + clear NO_PROXY/ALL_PROXY) → sandbox-exec child
- Integration test
- **Smoke test (macOS only):** run sandbox-exec with generated profile, curl an allowed HTTPS host through the proxy — validates mach service allowlist and TLS trust chain work

### Step 7: CLI wiring

- `hc <command>` calls exec orchestration
- `--dry-run` and `--print-profile` flags
- `hc claude`, `hc amp` work end-to-end
- Manual smoke test

### Step 8: Polish

- Error messages, `--verbose` flag
- Graceful shutdown, cleanup on SIGINT (proxy only, tmp dirs persist)

### Step 9: Integration Tests (macOS only)

- **Network bypass**: from inside sandbox, direct `curl` without proxy env must fail at socket level
- **Localhost port isolation**: only proxy port reachable outbound, `127.0.0.1:22` etc. blocked
- **Unix socket isolation**: attempt to open `/var/run/docker.sock` must fail in both tiers (unless explicitly allowed in permissive)
- **TLS trust**: `curl` through proxy to allowed host succeeds (validates mach service allowlist)
- **Blocked host**: request to non-allowed host returns 403 and appears in proxy.log
- **Port restriction**: request to allowed host on non-allowed port (e.g., `:22`) is rejected
- **DNS guard**: request to allowed hostname that resolves to private IP is rejected
- **IP literal rejection**: CONNECT to raw IP is rejected

## v2 Roadmap

Features documented for future implementation:

- **Secret injection + MITM**: Ephemeral CA, goproxy MITM mode, route-based header injection
- **Method/path filtering**: Proxy inspects decrypted HTTP requests for fine-grained control (requires MITM)
- **IP literal allowlisting**: Support IP addresses in allow config and request targets
- **`hc init-cluster`**: Scaffold k8s namespace with restricted PodSecurityStandard, NetworkPolicy, RBAC, disabled SA token mounting for safe agent access to local k8s clusters
- **Linux support**: Bubblewrap sandbox backend
- **Per-agent profiles**: Different allowlists/tiers per agent
- **Proxy log structured output**: JSON lines format for machine parsing
- **Sandbox the proxy itself**: Separate seatbelt profile for the proxy process to reduce impact of proxy parsing vulnerabilities

### k8s Security Notes

AI agents with kubectl access can escape the sandbox by scheduling pods that run outside seatbelt. Mitigation requires Kubernetes-native controls:

- Restricted PodSecurityStandard on agent namespace
- NetworkPolicy denying pod egress by default
- RBAC scoped to namespace only, no cluster-role bindings
- automountServiceAccountToken: false
- StorageClass restrictions (no PVC creation, or restricted provisioner)

The proxy layer can add defense-in-depth by filtering k8s API calls (blocking pod/deployment creation) once method/path filtering is implemented.
