package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	keyPath, certPath string
	keyTypeName       string
	keyType           KeyType
	chainPath         string
	csrPath           string
	approve           bool
)

var signCmd = &cobra.Command{
	Use:              "sign",
	Short:            "Issue leaf certificates or constrained intermediate CAs",
	Long:             `Sign an existing CSR, generate a key and leaf certificate, or issue a domain-constrained intermediate CA.`,
	PersistentPreRun: validateKeyType,
	Args:             cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
	},
}

func signInit() {
	signCmd.PersistentFlags().StringVar(&caKeyPath, "ca-key", "", "path to the CA key to use to sign the output certificate")
	_ = signCmd.MarkPersistentFlagRequired("ca-key")
	signCmd.PersistentFlags().StringVar(&caCertPath, "ca-cert", "", "path to the CA certificate to use to sign the output certificate")
	_ = signCmd.MarkPersistentFlagRequired("ca-cert")

	signCmd.PersistentFlags().IntVar(&keySize, "key-size", 4096, "key size to use")
	signCmd.PersistentFlags().StringVar(&keyTypeName, "key-type", "rsa", "key type to use, one of: rsa, ecdsa, ed25519")
	signCmd.PersistentFlags().StringVar(&chainPath, "chain", "", "PEM issuer ancestors in order, ending with the self-signed root (required for intermediate signers unless included in --ca-cert)")
	signCmd.PersistentFlags().IntVar(&certDays, "days", 365, "days for certificate validity, capped at issuer expiry")
	signCmd.AddCommand(intermediateCmd)
	intermediateInit()
	signCmd.AddCommand(certificateCmd)
	certificateInit()
}

// Both certificate types require exactly one source of subject and public key.
func validateSigningMode(cmd *cobra.Command) (bool, error) {
	if cmd.Flags().Changed("csr") {
		if cmd.Flags().Changed("subject") || cmd.Flags().Changed("key") || cmd.Flags().Changed("san") {
			return false, fmt.Errorf("--csr cannot be combined with --subject, --key, or --san")
		}
		if csrPath == "" {
			return false, fmt.Errorf("--csr requires a file path")
		}
		return true, nil
	}
	if !cmd.Flags().Changed("subject") || subject == "" || !cmd.Flags().Changed("key") || keyPath == "" {
		return false, fmt.Errorf("specify --subject and --key, or --csr")
	}
	return false, nil
}
