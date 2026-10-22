package cmd

import (
	"crypto/x509"

	"github.com/spf13/cobra"
)

// signCertificateFromCSR issues a leaf using the request's subject and key.
func signCertificateFromCSR(cmd *cobra.Command) error {
	if err := checkOutputPaths([]string{certPath}, []string{caKeyPath, caCertPath, chainPath, csrPath}); err != nil {
		return err
	}
	csr, err := loadCSR(csrPath)
	if err != nil {
		return err
	}
	template, err := newCertificateTemplate(csr.Subject, certDays)
	if err != nil {
		return err
	}
	template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	template.DNSNames, template.IPAddresses = csr.DNSNames, csr.IPAddresses
	template.EmailAddresses, template.URIs = csr.EmailAddresses, csr.URIs
	if err := approveCSR(cmd, csr); err != nil {
		return err
	}
	return loadAndSignCert(caCertPath, caKeyPath, template, csr.PublicKey, certPath)
}
