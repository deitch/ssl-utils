package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	rootCmd = &cobra.Command{Use: "ca"}
	verbose bool
)

func init() {
	rootCmd.AddCommand(initCmd)
	initInit()
	rootCmd.AddCommand(signCmd)
	signInit()
	rootCmd.AddCommand(readCmd)
	readInit()
	rootCmd.AddCommand(csrCmd)
	csrInit()
	rootCmd.AddCommand(convertCmd)
	convertInit()
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "print lots of output to stderr")
}

// Execute primary function for cobra
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
