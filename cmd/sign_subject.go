package cmd

import (
	"crypto"
	"crypto/x509"
	"log"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var signSubjectCmd = &cobra.Command{
	Use:   "subject",
	Short: "Generate a private key, generate a CSR and sign it",
	Long:  `Generate a private key, generate a CSR and sign it.`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			publicKey crypto.PublicKey
			template  x509.Certificate
		)
		_, publicKey, err := generateKeyPair(keyType, keySize, keyPath)
		if err != nil {
			log.Fatalf("error generating private key: %v", err)
		}
		name, err := parseSubject(subject)
		if err != nil {
			log.Fatalf("error parsing the subject: %v", err)
		}
		template = x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      *name,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour * 24 * time.Duration(certDays)),

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			IsCA:                  false,
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
		if err = loadAndSignCert(caCertPath, caKeyPath, &template, publicKey, certPath); err != nil {
			log.Fatalf("failed to sign cert: %v", err)
		}
	},
}

func signSubjectInit() {
	signSubjectCmd.Flags().StringVar(&keyPath, "key", "", "path to the save the generated key")
	signSubjectCmd.MarkFlagRequired("key")
	signSubjectCmd.Flags().StringVar(&certPath, "cert", "", "path to save the signed certificate")
	signSubjectCmd.MarkFlagRequired("cert")
	signSubjectCmd.Flags().StringVar(&subject, "subject", "", "distinguished name subject for the certificate in the format 'C=US,ST=NY,O=My Org,CN=server.myorg.com', also supports '/C=US/ST=NY/...' if starting with '/'")
	signSubjectCmd.MarkFlagRequired("subject")
	signSubjectCmd.Flags().StringVar(&saNames, "san", "", "subject alternative names (SAN) to use, comma-separated, e.g. '127.0.0.1,www.foo.com'")
}
