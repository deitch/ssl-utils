package cmd

import (
	"bufio"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"os"
	"time"

	"github.com/spf13/cobra"
)

var (
	csrPath string
	approve bool
)

var signCsrCmd = &cobra.Command{
	Use:   "sign",
	Short: "Sign a CSR",
	Long:  `Sign an existing CSR`,
	Run: func(cmd *cobra.Command, args []string) {
		var (
			publicKey crypto.PublicKey
			template  x509.Certificate
		)
		// get the CSR from the file
		csrBytes, err := ioutil.ReadFile(csrPath)
		if err != nil {
			log.Fatalf("unable to read CSR file %s: %v", csrPath, err)
		}
		block, _ := pem.Decode(csrBytes)
		csr, err := x509.ParseCertificateRequest(block.Bytes)
		if err != nil {
			log.Fatalf("unable to parse CSR file %s: %v", csrPath, err)
		}
		template = x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      csr.Subject,
			NotBefore:    time.Now(),
			NotAfter:     time.Now().Add(time.Hour * 24 * time.Duration(certDays)),

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			IsCA:                  false,
			DNSNames:              csr.DNSNames,
			IPAddresses:           csr.IPAddresses,
		}
		if !approve {
			reader := bufio.NewReader(os.Stdin)
			fmt.Printf("Approve certificate for %#v (y/n)? ", csr.Subject)
			text, _ := reader.ReadString('\n')
			if text != "Y" && text != "y" {
				log.Fatal("Not approved!")
			}
		}

		// load and sign
		if err = loadAndSignCert(caCertPath, caKeyPath, &template, publicKey, certPath); err != nil {
			log.Fatalf("failed to sign cert: %v", err)
		}
	},
}

func signCsrInit() {
	signCsrCmd.Flags().StringVar(&certPath, "cert", "", "path to save the signed certificate")
	signCsrCmd.MarkFlagRequired("cert")
	signCsrCmd.Flags().StringVar(&csrPath, "csr", "", "path to the CSR to sign; must specify one of --csr or --subject")
	signCsrCmd.MarkFlagRequired("csr")
	signCsrCmd.Flags().BoolVar(&approve, "approve", false, "auto-approve signing without checking, used only for CSR")
}
