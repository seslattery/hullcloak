package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:              "hc [flags] <command> [args...]",
	Short:            "Sandbox + allowlist proxy for AI agents",
	Version:          "0.1.0",
	TraverseChildren: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 && !printProfile {
			return cmd.Help()
		}
		return runWrap(cmd, args)
	},
	SilenceErrors: true,
	SilenceUsage:  true,
}

// Execute runs the root command.
func Execute() {
	args := os.Args[1:]
	if shouldRewriteArgs(args) {
		args = insertArgSeparator(args)
		rootCmd.SetArgs(args)
	}

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func isSubcommand(name string) bool {
	for _, cmd := range rootCmd.Commands() {
		if cmd.Name() == name {
			return true
		}
	}
	return name == "help"
}

func shouldRewriteArgs(args []string) bool {
	for _, arg := range args {
		if arg == "--" {
			return false
		}
		if strings.HasPrefix(arg, "-") {
			continue
		}
		return !isSubcommand(arg)
	}
	return false
}

func insertArgSeparator(args []string) []string {
	for i, arg := range args {
		if !strings.HasPrefix(arg, "-") {
			return append(append(args[:i:i], "--"), args[i:]...)
		}
	}
	return args
}

func init() {
	rootCmd.Flags().BoolVar(&verbose, "verbose", false, "Show verbose output")
	rootCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Print generated seatbelt profile without executing")
	rootCmd.Flags().BoolVar(&printProfile, "print-profile", false, "Print the SBPL profile and exit")
}
