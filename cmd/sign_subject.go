package cmd

import (
	"crypto/x509"
	"net"
	"strings"
)

// signCertificateFromSubject generates a key and issues a leaf certificate.
func signCertificateFromSubject() error {
	if err := checkOutputPaths([]string{keyPath, certPath}, []string{caKeyPath, caCertPath, chainPath}); err != nil {
		return err
	}
	name, err := parseSubject(subject)
	if err != nil {
		return err
	}
	template, err := newCertificateTemplate(*name, certDays)
	if err != nil {
		return err
	}
	template.KeyUsage = x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature
	template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if saNames != "" {
		for _, name := range strings.Split(saNames, ",") {
			if ip := net.ParseIP(name); ip != nil {
				template.IPAddresses = append(template.IPAddresses, ip)
			} else {
				template.DNSNames = append(template.DNSNames, name)
			}
		}
	}
	issuer, err := loadIssuer(caCertPath, caKeyPath, chainPath)
	if err != nil {
		return err
	}
	privateKey, publicKey, err := generatePrivateKey(keyType, keySize)
	if err != nil {
		return err
	}
	der, err := issuer.issue(template, publicKey)
	if err != nil {
		return err
	}
	if err := privateKeyToPEMFile(privateKey, keyPath); err != nil {
		return err
	}
	return certificateToPEMFile(der, certPath)
}
