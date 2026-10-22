package cmd

import "github.com/spf13/cobra"

var certificateCmd = &cobra.Command{
	Use:   "certificate",
	Short: "Issue a leaf certificate from a subject or CSR",
	Long:  "Generate a private key and leaf certificate with --subject and --key, or sign an existing --csr. Exactly one mode is required. CSR subjects and SANs come from the request.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		fromCSR, err := validateSigningMode(cmd)
		if err != nil {
			return err
		}
		if fromCSR {
			return signCertificateFromCSR(cmd)
		}
		return signCertificateFromSubject()
	},
}

func certificateInit() {
	f := certificateCmd.Flags()
	f.StringVar(&subject, "subject", "", "subject for the new certificate; cannot combine with --csr")
	f.StringVar(&keyPath, "key", "", "path for the generated private key; required with --subject")
	f.StringVar(&certPath, "cert", "", "path to save the signed certificate")
	_ = certificateCmd.MarkFlagRequired("cert")
	f.StringVar(&csrPath, "csr", "", "CSR to sign instead of generating a key; cannot combine with --subject, --key, or --san")
	f.StringVar(&saNames, "san", "", "comma-separated DNS/IP SANs for --subject mode")
	f.BoolVar(&approve, "approve", false, "approve signing a CSR without prompting")
}
