package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/seslattery/hullcloak/internal/config"
	hcexec "github.com/seslattery/hullcloak/internal/exec"
)

var (
	verbose      bool
	dryRun       bool
	printProfile bool
)

func runWrap(cmd *cobra.Command, args []string) error {
	cfg, err := loadConfig()
	if err != nil {
		return err
	}

	if printProfile {
		p, err := hcexec.ProfileOnly(cfg)
		if err != nil {
			return err
		}
		fmt.Fprintln(cmd.OutOrStdout(), p) //nolint:errcheck
		return nil
	}

	if dryRun {
		if len(args) == 0 {
			return fmt.Errorf("--dry-run requires a command")
		}
		p, err := hcexec.ProfileOnly(cfg)
		if err != nil {
			return err
		}
		out := cmd.OutOrStdout()
		fmt.Fprintln(out, p)                                             //nolint:errcheck
		fmt.Fprintf(out, "hc: would run: %s\n", strings.Join(args, " ")) //nolint:errcheck

		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		cwd, err = filepath.EvalSymlinks(cwd)
		if err != nil {
			return err
		}
		fmt.Fprintf(out, "hc: TMPDIR=%s/.hullcloak-tmp/tmp/\n", cwd)          //nolint:errcheck
		fmt.Fprintf(out, "hc: XDG_CACHE_HOME=%s/.hullcloak-tmp/cache\n", cwd) //nolint:errcheck
		if len(cfg.EnvPassthrough) > 0 {
			fmt.Fprintf(out, "hc: env_passthrough: %s\n", strings.Join(cfg.EnvPassthrough, ", ")) //nolint:errcheck
		}
		return nil
	}

	res, err := hcexec.Run(cmd.Context(), &hcexec.Options{
		Config:  cfg,
		Command: args,
		Verbose: verbose,
		Stdin:   cmd.InOrStdin(),
		Stdout:  cmd.OutOrStdout(),
		Stderr:  cmd.ErrOrStderr(),
	})
	if err != nil {
		return err
	}
	os.Exit(res.ExitCode)
	return nil
}

func loadConfig() (*config.Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("home dir: %w", err)
	}
	cfgPath := filepath.Join(home, ".hullcloak", "config.yaml")

	cfg, err := config.Load(cfgPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config not found at %s (run \"hc init\")", cfgPath)
		}
		return nil, fmt.Errorf("load config: %w", err)
	}
	return cfg, nil
}
