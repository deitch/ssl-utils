package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"strings"

	"github.com/spf13/cobra"
)

var readCmd = &cobra.Command{
	Use:   "read <file>",
	Short: "Read a certificate, CSR or key",
	Long:  `Read a certificate, CSR or key`,
	Args:  cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		readPath := args[0]
		// open and read the file
		b, err := ioutil.ReadFile(readPath)
		if err != nil {
			log.Fatalf("failed to read file %s: %v", readPath, err)
		}
		der, _ := pem.Decode(b)
		if der == nil {
			log.Fatalf("no valid PEM in file %s: %v", readPath, err)
		}
		switch {
		case der.Type == "CERTIFICATE":
			cert, err := x509.ParseCertificate(der.Bytes)
			if err != nil {
				log.Fatalf("failed to parse certificate: %v", err)
			}
			printCert(cert)
		case der.Type == "PRIVATE KEY" || strings.HasSuffix(der.Type, " PRIVATE KEY"):
			key, err := parsePrivateKey(der.Bytes)
			if err != nil {
				log.Fatalf("failed to parse private key: %v", err)
			}
			printKey(key)
		case der.Type == "CERTIFICATE REQUEST":
			csr, err := x509.ParseCertificateRequest(der.Bytes)
			if err != nil {
				log.Fatalf("unable to parse certificate signing request: %v", err)
			}
			printCsr(csr)
		default:
			// failed, error
			log.Fatalf("the file %s is not a key, certificate or signing request", readPath)
		}
	},
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}

	return nil, errors.New("tls: failed to parse private key")
}

func printCert(cert *x509.Certificate) {
	fmt.Printf("CERTIFICATE\n")
	fmt.Printf("\tSubject: %s\n", cert.Subject.String())
	fmt.Printf("\tIssuer: %s\n", cert.Issuer.String())
	fmt.Printf("\tValid from: %s\n", cert.NotBefore)
	fmt.Printf("\tValid until: %s\n", cert.NotAfter)
	fmt.Printf("\tKey Usage: %s\n", strings.Join(parseKeyUsage(cert.KeyUsage), ","))
	fmt.Printf("\tExtended Key Usage: %s\n", strings.Join(parseExtKeyUsage(cert.ExtKeyUsage), ","))
	fmt.Printf("\tCA: %v\n", cert.IsCA)
	fmt.Printf("\tSAN: %v %v\n", cert.DNSNames, cert.IPAddresses)
}
func printKey(rawKey crypto.PrivateKey) {
	switch rawKey.(type) {
	case *rsa.PrivateKey:
		fmt.Printf("RSA PRIVATE KEY\n")
	case *ecdsa.PrivateKey:
		fmt.Printf("ECDSA PRIVATE KEY\n")
	case ed25519.PrivateKey:
		fmt.Printf("ED25519 PRIVATE KEY\n")
	default:
		fmt.Printf("unknown private key type\n")
	}
}

func printCsr(csr *x509.CertificateRequest) {
	fmt.Printf("CERTIFICATE REQUEST\n")
	fmt.Printf("\tSubject: %s\n", csr.Subject.String())
	fmt.Printf("\tSAN: %v %v\n", csr.DNSNames, csr.IPAddresses)
}

func parseKeyUsage(u x509.KeyUsage) []string {
	ret := make([]string, 0)
	if u&x509.KeyUsageDigitalSignature == x509.KeyUsageDigitalSignature {
		ret = append(ret, "DigitalSignature")
	}
	if u&x509.KeyUsageContentCommitment == x509.KeyUsageContentCommitment {
		ret = append(ret, "ContentCommitment")
	}
	if u&x509.KeyUsageKeyEncipherment == x509.KeyUsageKeyEncipherment {
		ret = append(ret, "KeyEncipherment")
	}
	if u&x509.KeyUsageDataEncipherment == x509.KeyUsageDataEncipherment {
		ret = append(ret, "DataEncipherment")
	}
	if u&x509.KeyUsageKeyAgreement == x509.KeyUsageKeyAgreement {
		ret = append(ret, "KeyAgreement")
	}
	if u&x509.KeyUsageCertSign == x509.KeyUsageCertSign {
		ret = append(ret, "CertSign")
	}
	if u&x509.KeyUsageCRLSign == x509.KeyUsageCRLSign {
		ret = append(ret, "CRLSign")
	}
	if u&x509.KeyUsageEncipherOnly == x509.KeyUsageEncipherOnly {
		ret = append(ret, "EncipherOnly")
	}
	if u&x509.KeyUsageDecipherOnly == x509.KeyUsageDecipherOnly {
		ret = append(ret, "DecipherOnly")
	}
	return ret
}

func parseExtKeyUsage(usages []x509.ExtKeyUsage) []string {
	ret := make([]string, 0)

	for _, u := range usages {
		switch u {
		case x509.ExtKeyUsageAny:
			ret = append(ret, "Any")
		case x509.ExtKeyUsageServerAuth:
			ret = append(ret, "ServerAuth")
		case x509.ExtKeyUsageClientAuth:
			ret = append(ret, "ClientAuth")
		case x509.ExtKeyUsageCodeSigning:
			ret = append(ret, "CodeSigning")
		case x509.ExtKeyUsageEmailProtection:
			ret = append(ret, "EmailProtection")
		case x509.ExtKeyUsageIPSECEndSystem:
			ret = append(ret, "IPSECEndSystem")
		case x509.ExtKeyUsageIPSECTunnel:
			ret = append(ret, "IPSECTunnel")
		case x509.ExtKeyUsageIPSECUser:
			ret = append(ret, "IPSECUser")
		case x509.ExtKeyUsageTimeStamping:
			ret = append(ret, "TimeStamping")
		case x509.ExtKeyUsageOCSPSigning:
			ret = append(ret, "OCSPSigning")
		case x509.ExtKeyUsageMicrosoftServerGatedCrypto:
			ret = append(ret, "MicrosoftServerGatedCrypto")
		case x509.ExtKeyUsageNetscapeServerGatedCrypto:
			ret = append(ret, "NetscapeServerGatedCrypto")
		case x509.ExtKeyUsageMicrosoftCommercialCodeSigning:
			ret = append(ret, "MicrosoftCommercialCodeSigning")
		case x509.ExtKeyUsageMicrosoftKernelCodeSigning:
			ret = append(ret, "MicrosoftKernelCodeSigning")
		}
	}

	return ret
}

func readInit() {
}
