package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var cleanCmd = &cobra.Command{
	Use:   "clean",
	Short: "Remove .hullcloak-tmp/ from current directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}

		dir := filepath.Join(cwd, ".hullcloak-tmp")

		if _, err := os.Stat(dir); os.IsNotExist(err) {
			fmt.Println("Nothing to clean")
			return nil
		}

		if err := os.RemoveAll(dir); err != nil {
			return err
		}

		fmt.Println("Removed .hullcloak-tmp/")
		return nil
	},
}

func init() {
	rootCmd.AddCommand(cleanCmd)
}
