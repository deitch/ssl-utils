package cmd

import (
	"crypto/x509"
	"log"
	"math/big"
	"time"

	"github.com/spf13/cobra"
)

var (
	keySize, certDays int
	subject           string
)

var initCmd = &cobra.Command{
	Use:    "init",
	Short:  "Initialize a CA",
	Long:   `Initialize a CA with a key and self-signed certificate`,
	PreRun: validateKeyType,
	Run: func(cmd *cobra.Command, args []string) {
		privateKey, publicKey, err := generateKeyPair(keyType, keySize, caKeyPath)
		if err != nil {
			log.Fatalf("error generating private key: %v", err)
		}
		name, err := parseSubject(subject)
		if err != nil {
			log.Fatalf("error parsing the subject: %v", err)
		}
		template := x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      *name,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour * 24 * time.Duration(certDays)),

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		err = signCert(&template, &template, publicKey, privateKey, caCertPath)
		if err != nil {
			log.Fatalf("Failed to create certificate: %s", err)
		}
	},
}

func initInit() {
	initCmd.Flags().StringVar(&caKeyPath, "ca-key", "", "path to save the CA key")
	initCmd.MarkFlagRequired("ca-key")
	initCmd.Flags().StringVar(&caCertPath, "ca-cert", "", "path to save the CA certificate")
	initCmd.MarkFlagRequired("ca-cert")
	initCmd.Flags().StringVar(&subject, "subject", "", "distinguished name subject for the certificate in the format 'C=US,ST=NY,O=My Org,CN=server.myorg.com', also supports '/C=US/ST=NY/...' if starting with '/'; must specify one of --csr or --subject")
	initCmd.MarkFlagRequired("subject")
	initCmd.Flags().IntVar(&keySize, "key-size", 4096, "key size to use")
	initCmd.Flags().StringVar(&keyTypeName, "key-type", "rsa", "key type to use, one of: rsa, ecdsa, ed25519")
	initCmd.Flags().IntVar(&certDays, "days", 365, "days for certificate validity")
}
