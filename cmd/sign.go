package cmd

import (
	"github.com/spf13/cobra"
)

var (
	keyPath, certPath string
)

var signCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a CSR or generate and sign it",
	Long:  `Sign an existing CSR, or generate a key and CSR and sign it.`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func signInit() {
	signCmd.PersistentFlags().StringVar(&caKeyPath, "ca-key", "", "path to the CA key to use to sign the output certificate")
	signCmd.MarkFlagRequired("ca-key")
	signCmd.PersistentFlags().StringVar(&caCertPath, "ca-cert", "", "path to the CA certificate to use to sign the output certificate")
	signCmd.MarkFlagRequired("ca-cert")

	signCmd.PersistentFlags().IntVar(&keySize, "key-size", 4096, "key size to use")
	signCmd.AddCommand(signCsrCmd)
	signCsrInit()
	signCmd.AddCommand(signSubjectCmd)
	signSubjectInit()
}
