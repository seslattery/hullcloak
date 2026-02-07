package env

import "strings"

var secretSuffixes = []string{
	"_KEY",
	"_TOKEN",
	"_SECRET",
	"_PASSWORD",
	"_CREDENTIAL",
	"_CREDENTIALS",
	"_AUTH",
	"_PRIVATE",
}

var sensitiveVars = map[string]bool{
	"AWS_ACCESS_KEY_ID":  true,
	"DOCKER_AUTH_CONFIG": true,
	"KUBECONFIG":         true,
	"PGPASSWORD":         true,
	"MYSQL_PWD":          true,
}

func IsSecret(key string) bool {
	upper := strings.ToUpper(key)
	if sensitiveVars[upper] {
		return true
	}
	for _, s := range secretSuffixes {
		if strings.HasSuffix(upper, s) {
			return true
		}
	}
	return false
}

type Options struct {
	ProxyAddr      string
	TmpDir         string
	CacheDir       string
	EnvPassthrough []string
}

func Build(parent []string, opts Options) []string {
	passthrough := make(map[string]bool, len(opts.EnvPassthrough))
	for _, k := range opts.EnvPassthrough {
		passthrough[strings.ToUpper(k)] = true
	}

	env := make([]string, 0, len(parent)+12)
	for _, e := range parent {
		key, _, _ := strings.Cut(e, "=")
		upper := strings.ToUpper(key)

		switch upper {
		case "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY":
			continue
		case "TMPDIR":
			if opts.TmpDir != "" {
				continue
			}
		case "XDG_CACHE_HOME":
			if opts.CacheDir != "" {
				continue
			}
		}

		if passthrough[upper] {
			env = append(env, e)
			continue
		}
		if IsSecret(key) {
			continue
		}
		env = append(env, e)
	}

	for _, k := range []string{"HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"} {
		env = append(env, k+"="+opts.ProxyAddr)
	}
	for _, k := range []string{"NO_PROXY", "no_proxy", "ALL_PROXY", "all_proxy"} {
		env = append(env, k+"=")
	}
	if opts.TmpDir != "" {
		env = append(env, "TMPDIR="+opts.TmpDir)
	}
	if opts.CacheDir != "" {
		env = append(env, "XDG_CACHE_HOME="+opts.CacheDir)
	}
	return env
}

func Stripped(parent []string, passthrough []string) []string {
	pt := make(map[string]bool, len(passthrough))
	for _, k := range passthrough {
		pt[strings.ToUpper(k)] = true
	}

	var stripped []string
	for _, e := range parent {
		key, _, _ := strings.Cut(e, "=")
		if pt[strings.ToUpper(key)] {
			continue
		}
		if IsSecret(key) {
			stripped = append(stripped, key)
		}
	}
	return stripped
}
