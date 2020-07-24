package cmd

import (
	"crypto/x509"
	"log"
	"net"
	"strings"

	"github.com/spf13/cobra"
)

var csrCmd = &cobra.Command{
	Use:   "csr",
	Short: "Generate a private key, generate a CSR",
	Long:  `Generate a private key, generate a CSR.`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			template x509.CertificateRequest
		)
		key, _, err := generateKeyPair(keyType, keySize, keyPath)
		if err != nil {
			log.Fatalf("error generating private key: %v", err)
		}
		name, err := parseSubject(subject)
		if err != nil {
			log.Fatalf("error parsing the subject: %v", err)
		}
		template = x509.CertificateRequest{
			Subject: *name,
		}
		if saNames != "" {
			sans := strings.Split(saNames, ",")
			sansDNS := make([]string, 0)
			sansIps := make([]net.IP, 0)
			for _, s := range sans {
				ip := net.ParseIP(s)
				if ip == nil {
					sansDNS = append(sansDNS, s)
				} else {
					sansIps = append(sansIps, ip)
				}
			}
			template.DNSNames = sansDNS
			template.IPAddresses = sansIps
		}

		// load and sign
		if err := saveCSR(&template, key, csrPath); err != nil {
			log.Fatalf("failed to save CSR: %v", err)
		}
	},
}

func csrInit() {
	csrCmd.Flags().StringVar(&keyPath, "key", "", "path to the save the generated key")
	csrCmd.MarkFlagRequired("key")
	csrCmd.Flags().StringVar(&csrPath, "csr", "", "path to the save the generated CSR")
	csrCmd.MarkFlagRequired("csr")
	csrCmd.Flags().StringVar(&subject, "subject", "", "distinguished name subject for the certificate in the format 'C=US,ST=NY,O=My Org,CN=server.myorg.com', also supports '/C=US/ST=NY/...' if starting with '/'")
	csrCmd.MarkFlagRequired("subject")
	csrCmd.Flags().StringVar(&saNames, "san", "", "subject alternative names (SAN) to use, comma-separated, e.g. '127.0.0.1,www.foo.com'")
}
