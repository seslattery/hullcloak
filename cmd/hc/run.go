package main

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	verbose      bool
	dryRun       bool
	printProfile bool
)

func runWrap(cmd *cobra.Command, args []string) error {
	fmt.Println("hc: wrap not implemented yet")
	return nil
}
