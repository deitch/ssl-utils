package cmd

import (
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
	rootCmd.PersistentFlags().BoolVar(&verbose, "verbose", false, "print lots of output to stderr")
}

// Execute primary function for cobra
func Execute() {
	rootCmd.Execute()
}
