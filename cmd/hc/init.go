package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var defaultConfig = `# HullCloak configuration
# See: https://github.com/seslattery/veilwarden/tree/main/hullcloak

version: 1

tier: strict

allow:
  - api.anthropic.com
  - api.openai.com
  - "*.githubusercontent.com"
  - api.github.com
  - registry.npmjs.org

# Override default allowed ports (default: [443, 80])
# allow_ports: [443, 80, 8080]

# Extra readable paths beyond system paths (strict tier only)
# Must be absolute paths. Tilde (~) is expanded.
# allow_read:
#   - /usr/local/share

# Extra writable paths beyond cwd (both tiers)
# Must be absolute paths. Tilde (~) is expanded.
# allow_write:
#   - /tmp

# Unix sockets to allow (permissive tier only, denied in strict)
# allow_unix_sockets:
#   - /var/run/docker.sock

# Env vars to preserve despite matching strip patterns
# env_passthrough:
#   - ANTHROPIC_API_KEY
#   - OPENAI_API_KEY
`

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Create ~/.hullcloak/config.yaml with example configuration",
	RunE:  runInit,
}

func init() {
	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("cannot determine home directory: %w", err)
	}

	configDir := filepath.Join(home, ".hullcloak")
	if err := os.MkdirAll(configDir, 0o755); err != nil {
		return fmt.Errorf("failed to create %s: %w", configDir, err)
	}

	configPath := filepath.Join(configDir, "config.yaml")
	if _, err := os.Stat(configPath); err == nil {
		fmt.Fprintf(os.Stderr, "Config already exists: %s (skipping)\n", configPath)
		return nil
	}

	if err := os.WriteFile(configPath, []byte(defaultConfig), 0o644); err != nil {
		return fmt.Errorf("failed to write %s: %w", configPath, err)
	}

	fmt.Println("Created ~/.hullcloak/config.yaml")
	fmt.Println()
	fmt.Println("Remember to add .hullcloak-tmp/ to your .gitignore")

	return nil
}
