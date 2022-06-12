package cmd

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/spf13/cobra"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

var password string

var convertCmd = &cobra.Command{
	Use:   "convert",
	Short: "convert between formats",
	Long:  `Convert between formats, such as pkcs12 and pem`,
}

var convertPkcs12Cmd = &cobra.Command{
	Use:   "pkcs12",
	Short: "read and write pkcs12 file formats",
	Long:  `Read and write pkcs12 file formats`,
}

var convertPkcs12ReadCmd = &cobra.Command{
	Use:   "read <pkcs12 file>",
	Short: "read a pkcs12 file and output its component parts as pem",
	Long:  `read a pkcs12 file and output its component parts as pem`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pkcsFile := args[0]
		// open and read the file
		b, err := ioutil.ReadFile(pkcsFile)
		if err != nil {
			log.Fatalf("failed to read file %s: %v", pkcsFile, err)
		}

		// read the pkcs12 file
		key, cert, chain, err := pkcs12.DecodeChain(b, password)
		if err != nil {
			log.Fatalf("failed to decode file %s: %v", pkcsFile, err)
		}
		// write the outputs
		if key != nil {
			if err := privateKeyToPEMFile(key, keyPath); err != nil {
				log.Fatalf("failed to write key file at %s: %v", keyPath, err)
			}
		}
		if cert != nil {
			if err := certificateToPEMFile(cert.Raw, certPath); err != nil {
				log.Fatalf("failed to write cert file at %s: %v", certPath, err)
			}
		}
		if chain != nil && len(chain) > 0 {
			bs := [][]byte{}
			for _, cert := range chain {
				bs = append(bs, cert.Raw)
			}
			if err := certificatesToPEMFile(bs, caCertPath); err != nil {
				log.Fatalf("failed to write CA chain file at %s: %v", caCertPath, err)
			}
		}
	},
}

var convertPkcs12WriteCmd = &cobra.Command{
	Use:   "write <pkcs12 file>",
	Short: "write a pkcs12 file from pem inputs",
	Long:  `write a pkcs12 file from pem inputs`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pkcsFile := args[0]
		var (
			key         crypto.PrivateKey
			cert        *x509.Certificate
			chain       []*x509.Certificate
			pkcs12Bytes []byte
			err         error
		)
		// open and read the input files
		if keyPath != "" {
			b, err := ioutil.ReadFile(keyPath)
			if err != nil {
				log.Fatalf("failed to read key file %s: %v", keyPath, err)
			}
			der, _ := pem.Decode(b)
			if der == nil {
				log.Fatalf("no valid PEM in key file %s: %v", keyPath, err)
			}
			if !(der.Type == "PRIVATE KEY" || strings.HasSuffix(der.Type, " PRIVATE KEY")) {
				log.Fatalf("key file %s does not contain private key", keyPath)
			}
			key, err = parsePrivateKey(der.Bytes)
			if err != nil {
				log.Fatalf("failed to parse private key from %s: %v", keyPath, err)
			}
		}
		if certPath != "" {
			b, err := ioutil.ReadFile(certPath)
			if err != nil {
				log.Fatalf("failed to read cert file %s: %v", certPath, err)
			}
			der, _ := pem.Decode(b)
			if der == nil {
				log.Fatalf("no valid PEM in cert file %s: %v", certPath, err)
			}
			if der.Type != "CERTIFICATE" {
				log.Fatalf("cert file %s does not contain certificate", certPath)
			}
			cert, err = x509.ParseCertificate(der.Bytes)
			if err != nil {
				log.Fatalf("failed to parse certificate from %s: %v", certPath, err)
			}
		}

		if caCertPath != "" {
			b, err := ioutil.ReadFile(caCertPath)
			if err != nil {
				log.Fatalf("failed to read CA cert chain file %s: %v", caCertPath, err)
			}
			der, _ := pem.Decode(b)
			if der == nil {
				log.Fatalf("no valid PEM in cert file %s: %v", certPath, err)
			}
			if der.Type != "CERTIFICATE" {
				log.Fatalf("CA cert file %s does not contain certificate", certPath)
			}
			cert, err := x509.ParseCertificate(der.Bytes)
			if err != nil {
				log.Fatalf("failed to parse CA certificate from %s: %v", certPath, err)
			}
			chain = append(chain, cert)
		}
		// now write the pkcs12 file
		if key != nil {
			pkcs12Bytes, err = pkcs12.Encode(rand.Reader, key, cert, chain, password)
			if err != nil {
				log.Fatalf("failed to pkcs12 encode key, cert and chain: %v", err)
			}
		} else {
			pkcs12Bytes, err = pkcs12.EncodeTrustStore(rand.Reader, chain, password)
			if err != nil {
				log.Fatalf("failed to pkcs12 encode chain: %v", err)
			}
		}
		if err := os.WriteFile(pkcsFile, pkcs12Bytes, 0600); err != nil {
			log.Fatalf("failed to write pkcs12 file %s: %v", pkcsFile, err)
		}
	},
}

func convertInit() {
	convertCmd.AddCommand(convertPkcs12Cmd)
	convertPkcs12Init()
}
func convertPkcs12Init() {
	convertPkcs12Cmd.AddCommand(convertPkcs12ReadCmd)
	convertPkcs12Cmd.AddCommand(convertPkcs12WriteCmd)
	convertPkcs12Cmd.PersistentFlags().StringVar(&caCertPath, "ca", "", "path to CA pem file")
	convertPkcs12Cmd.PersistentFlags().StringVar(&certPath, "cert", "", "path to cert pem file")
	convertPkcs12Cmd.PersistentFlags().StringVar(&keyPath, "key", "", "path to key pem file")

	convertPkcs12ReadInit()
	convertPkcs12WriteInit()
}
func convertPkcs12ReadInit() {
	convertPkcs12ReadCmd.Flags().StringVar(&password, "password", "", "password to read pkcs12 file")
}
func convertPkcs12WriteInit() {
	convertPkcs12WriteCmd.Flags().StringVar(&password, "password", "", "password to encrypt pkcs12 file, optional")
}

/*
From pem to pkcs12
ca convert --to pkcs12 --ca --cert --key
ca convert --to pem --pkcs12

ca convert pkcs12 write --file --ca --cert --key
ca convert pkcs12 read --file --ca --cert --key
*/
