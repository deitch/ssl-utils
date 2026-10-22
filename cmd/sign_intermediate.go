package cmd

import (
	"bufio"
	"crypto"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var (
	permittedDomains, excludedDomains []string
	maxPathLen                        int
)

var intermediateCmd = &cobra.Command{
	Use:   "intermediate",
	Short: "Issue a domain-constrained intermediate CA",
	Long:  "Generate an intermediate CA key and certificate, or sign an existing CSR. Requires explicit permitted DNS domains. Ancestors must be supplied through --chain or bundled in --ca-cert.",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		fromCSR, err := validateSigningMode(cmd)
		if err != nil {
			return err
		}
		if maxPathLen < 0 {
			return fmt.Errorf("--max-path-len must be zero or positive")
		}
		for _, domain := range append(append([]string{}, permittedDomains...), excludedDomains...) {
			if err := validateDomain(domain, true); err != nil {
				return err
			}
		}
		if len(permittedDomains) == 0 {
			return fmt.Errorf("at least one --permit-dns is required")
		}
		i, err := loadIssuer(caCertPath, caKeyPath, chainPath)
		if err != nil {
			return err
		}
		var template *x509.Certificate
		var publicKey crypto.PublicKey
		var privateKey crypto.PrivateKey
		if fromCSR {
			csr, err := loadCSR(csrPath)
			if err != nil {
				return err
			}
			template, err = newCertificateTemplate(csr.Subject, certDays)
			if err != nil {
				return err
			}
			template.DNSNames, template.IPAddresses = csr.DNSNames, csr.IPAddresses
			template.EmailAddresses, template.URIs = csr.EmailAddresses, csr.URIs
			publicKey = csr.PublicKey
			if err := approveCSR(cmd, csr); err != nil {
				return err
			}
		} else {
			name, err := parseSubject(subject)
			if err != nil {
				return err
			}
			template, err = newCertificateTemplate(*name, certDays)
			if err != nil {
				return err
			}
			privateKey, publicKey, err = generatePrivateKey(keyType, keySize)
			if err != nil {
				return err
			}
		}
		template.IsCA = true
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature
		template.MaxPathLen, template.MaxPathLenZero = maxPathLen, maxPathLen == 0
		template.PermittedDNSDomainsCritical = true
		template.PermittedDNSDomains = append([]string{}, permittedDomains...)
		template.ExcludedDNSDomains = append([]string{}, excludedDomains...)
		if err := checkDNSOnlyNames(template); err != nil {
			return err
		}
		if err := checkDNSNames(template.DNSNames, template); err != nil {
			return err
		}
		der, err := i.issue(template, publicKey)
		if err != nil {
			return err
		}
		// Intermediate output must not overwrite existing files, especially CA inputs.
		// No output is created until the certificate passes all policy checks.
		f, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return err
		}
		saved, keyCreated := false, false
		defer func() {
			if !saved {
				_ = f.Close()
				_ = os.Remove(certPath)
				if keyCreated {
					_ = os.Remove(keyPath)
				}
			}
		}()
		if privateKey != nil {
			if err := writeNewPrivateKey(privateKey, keyPath); err != nil {
				return err
			}
			keyCreated = true
		}
		if err := writeCertificate(f, der); err != nil {
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
		saved = true
		return nil
	},
}

func approveCSR(cmd *cobra.Command, csr *x509.CertificateRequest) error {
	if approve {
		return nil
	}
	if _, err := fmt.Fprintf(cmd.OutOrStdout(), "Approve certificate for %s (y/n)? ", csr.Subject); err != nil {
		return err
	}
	answer, err := bufio.NewReader(cmd.InOrStdin()).ReadString('\n')
	if err != nil {
		return fmt.Errorf("could not read CSR approval: %w", err)
	}
	if !strings.EqualFold(strings.TrimSpace(answer), "y") {
		return fmt.Errorf("CSR not approved")
	}
	return nil
}

func intermediateInit() {
	f := intermediateCmd.Flags()
	f.StringVar(&subject, "subject", "", "subject for the new intermediate CA")
	f.StringVar(&keyPath, "key", "", "path for the generated intermediate key (must not exist)")
	f.StringVar(&certPath, "cert", "", "path for the intermediate certificate (must not exist)")
	_ = intermediateCmd.MarkFlagRequired("cert")
	f.StringVar(&csrPath, "csr", "", "CSR to sign instead of generating a key; cannot combine with --subject or --key")
	f.BoolVar(&approve, "approve", false, "approve signing a CSR without prompting")
	f.StringSliceVar(&permittedDomains, "permit-dns", nil, "permitted DNS subtree, repeatable or comma-separated; .example.com permits subdomains only")
	f.StringSliceVar(&excludedDomains, "exclude-dns", nil, "excluded DNS subtree, repeatable or comma-separated")
	f.IntVar(&maxPathLen, "max-path-len", 0, "number of additional intermediate CA levels permitted")
}
