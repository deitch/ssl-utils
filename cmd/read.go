package cmd

import (
	"github.com/spf13/cobra"
)

var readPath string

var readCmd = &cobra.Command{
	Use:   "read",
	Short: "Read a certificate, CSR or key",
	Long:  `Read a certificate, CSR or key`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func readInit() {
	readCmd.Flags().StringVar(&readPath, "path", "", "path to file to read")
	readCmd.MarkFlagRequired("readPath")
}
