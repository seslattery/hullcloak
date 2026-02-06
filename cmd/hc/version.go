package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print hc version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("hc version " + rootCmd.Version)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
