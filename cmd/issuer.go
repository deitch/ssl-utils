package cmd

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// issuer contains an explicitly supplied, ordered chain from signer to root.
// A missing ancestor must never silently turn an intermediate into a trust anchor.
type issuer struct {
	chain []*x509.Certificate
	key   crypto.PrivateKey
}

func newCertificateTemplate(subject pkix.Name, days int) (*x509.Certificate, error) {
	if days <= 0 || int64(days) > (1<<63-1)/int64(24*time.Hour) {
		return nil, fmt.Errorf("--days must be positive and fit in a time.Duration")
	}
	// Positive random 128-bit serials avoid collisions across independent invocations.
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	serial.Add(serial, big.NewInt(1))
	now := time.Now()
	return &x509.Certificate{
		SerialNumber: serial, Subject: subject,
		NotBefore: now, NotAfter: now.Add(time.Duration(days) * 24 * time.Hour),
		BasicConstraintsValid: true,
	}, nil
}

func parseCertificates(b []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	for len(bytes.TrimSpace(b)) > 0 {
		block, rest := pem.Decode(b)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("expected a PEM certificate chain")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		b = rest
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("empty certificate chain")
	}
	return certs, nil
}

func loadIssuer(certPath, keyPath, ancestorsPath string) (*issuer, error) {
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read CA cert/key: %w", err)
	}
	i := &issuer{key: pair.PrivateKey}
	for _, der := range pair.Certificate {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, err
		}
		i.chain = append(i.chain, cert)
	}
	if ancestorsPath != "" {
		b, err := os.ReadFile(ancestorsPath)
		if err != nil {
			return nil, err
		}
		ancestors, err := parseCertificates(b)
		if err != nil {
			return nil, err
		}
		i.chain = append(i.chain, ancestors...)
	}
	if err := i.validate(); err != nil {
		return nil, err
	}
	return i, nil
}

func (i *issuer) validate() error {
	if len(i.chain) == 0 {
		return fmt.Errorf("missing issuer chain")
	}
	now := time.Now()
	for n, cert := range i.chain {
		if !cert.BasicConstraintsValid || !cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("issuer %q is not a certificate-signing CA", cert.Subject)
		}
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return fmt.Errorf("issuer %q is outside its validity period", cert.Subject)
		}
		if cert.MaxPathLen >= 0 && (cert.MaxPathLenZero || cert.MaxPathLen > 0) && n > cert.MaxPathLen {
			return fmt.Errorf("issuer chain exceeds path length for %q", cert.Subject)
		}
		for _, previous := range i.chain[:n] {
			if bytes.Equal(previous.RawSubject, cert.RawSubject) {
				return fmt.Errorf("duplicate CA subjects in issuer chain are not supported")
			}
		}
		parent := cert
		if n+1 < len(i.chain) {
			parent = i.chain[n+1]
		}
		if !bytes.Equal(cert.RawIssuer, parent.RawSubject) {
			return fmt.Errorf("issuer chain must be ordered and end with a self-signed root; supply missing ancestors using --chain")
		}
		if err := cert.CheckSignatureFrom(parent); err != nil {
			return fmt.Errorf("invalid issuer chain: %w", err)
		}
	}
	_, err := i.chain[0].Verify(i.verifyOptions(x509.ExtKeyUsageAny))
	if err != nil {
		return fmt.Errorf("invalid issuer chain: %w", err)
	}
	return nil
}

func (i *issuer) verifyOptions(usage x509.ExtKeyUsage) x509.VerifyOptions {
	roots, intermediates := x509.NewCertPool(), x509.NewCertPool()
	roots.AddCert(i.chain[len(i.chain)-1])
	for _, cert := range i.chain[:len(i.chain)-1] {
		intermediates.AddCert(cert)
	}
	return x509.VerifyOptions{Roots: roots, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{usage}}
}

func (i *issuer) issue(template *x509.Certificate, publicKey crypto.PublicKey) ([]byte, error) {
	if err := i.validate(); err != nil {
		return nil, err
	}
	if !template.NotAfter.After(template.NotBefore) {
		return nil, fmt.Errorf("invalid certificate validity")
	}
	for n, ca := range i.chain {
		if template.NotBefore.Before(ca.NotBefore) {
			return nil, fmt.Errorf("certificate starts before issuer validity")
		}
		if template.NotAfter.After(ca.NotAfter) {
			template.NotAfter = ca.NotAfter
		}
		if template.IsCA {
			if err := checkDelegation(template, ca, n); err != nil {
				return nil, err
			}
		}
		if len(ca.PermittedDNSDomains) > 0 || len(ca.ExcludedDNSDomains) > 0 {
			if err := checkDNSOnlyNames(template); err != nil {
				return nil, err
			}
			if err := checkDNSNames(template.DNSNames, ca); err != nil {
				return nil, err
			}
		}
	}
	if !template.NotAfter.After(template.NotBefore) {
		return nil, fmt.Errorf("issuer expires before certificate validity begins")
	}
	b, err := x509.CreateCertificate(rand.Reader, template, i.chain[0], publicKey, i.key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		return nil, err
	}
	usages := template.ExtKeyUsage
	if len(usages) == 0 {
		usages = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}
	for _, usage := range usages {
		if _, err := cert.Verify(i.verifyOptions(usage)); err != nil {
			return nil, fmt.Errorf("issued certificate violates issuer chain: %w", err)
		}
	}
	return b, nil
}

func checkDelegation(child, parent *x509.Certificate, distance int) error {
	if bytes.Equal(child.RawSubject, parent.RawSubject) && len(child.RawSubject) != 0 || child.Subject.String() == parent.Subject.String() {
		return fmt.Errorf("intermediate subject must differ from every ancestor")
	}
	if parent.MaxPathLen >= 0 && (parent.MaxPathLenZero || parent.MaxPathLen > 0) {
		remaining := parent.MaxPathLen - distance - 1
		if remaining < 0 || child.MaxPathLen < 0 || child.MaxPathLen > remaining || (child.MaxPathLen == 0 && !child.MaxPathLenZero) {
			return fmt.Errorf("intermediate exceeds issuer path length constraint")
		}
	}
	for _, domain := range child.PermittedDNSDomains {
		if len(parent.PermittedDNSDomains) > 0 {
			allowed := false
			for _, permitted := range parent.PermittedDNSDomains {
				allowed = allowed || domainSubset(domain, permitted)
			}
			if !allowed {
				return fmt.Errorf("intermediate domain %q widens issuer permissions", domain)
			}
		}
		for _, excluded := range parent.ExcludedDNSDomains {
			if domainSubset(domain, excluded) {
				return fmt.Errorf("intermediate domain %q is excluded by issuer", domain)
			}
		}
	}
	// Copy exclusions as defense in depth; ancestors still apply during verification.
	for _, excluded := range parent.ExcludedDNSDomains {
		if !containsDomain(child.ExcludedDNSDomains, excluded) {
			child.ExcludedDNSDomains = append(child.ExcludedDNSDomains, excluded)
		}
	}
	return nil
}

func containsDomain(domains []string, target string) bool {
	for _, domain := range domains {
		if strings.EqualFold(domain, target) {
			return true
		}
	}
	return false
}

// domainSubset compares complete DNS subtrees, including leading-dot semantics.
func domainSubset(child, parent string) bool {
	c, p := strings.ToLower(strings.TrimPrefix(child, ".")), strings.ToLower(strings.TrimPrefix(parent, "."))
	if c == p {
		return !strings.HasPrefix(parent, ".") || strings.HasPrefix(child, ".")
	}
	return strings.HasSuffix(c, "."+p)
}

func validateDomain(domain string, constraint bool) error {
	name := domain
	if constraint {
		name = strings.TrimPrefix(name, ".")
	} else {
		name = strings.TrimPrefix(name, "*.")
	}
	if name == "" || len(name) > 253 || net.ParseIP(name) != nil {
		return fmt.Errorf("invalid DNS domain %q", domain)
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return fmt.Errorf("invalid DNS domain %q", domain)
		}
		for _, c := range label {
			valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
			if !valid {
				return fmt.Errorf("invalid DNS domain %q (use ASCII/punycode names)", domain)
			}
		}
	}
	return nil
}

func checkDNSOnlyNames(cert *x509.Certificate) error {
	if len(cert.IPAddresses) > 0 || len(cert.EmailAddresses) > 0 || len(cert.URIs) > 0 {
		return fmt.Errorf("DNS-constrained issuers cannot issue IP, email, or URI identities")
	}
	if !cert.IsCA && len(cert.DNSNames) == 0 {
		return fmt.Errorf("DNS-constrained issuers require DNS SANs; common name alone is insufficient")
	}
	return nil
}

func checkDNSNames(names []string, ca *x509.Certificate) error {
	for _, name := range names {
		if err := validateDomain(name, false); err != nil {
			return err
		}
		allowed := len(ca.PermittedDNSDomains) == 0
		for _, permitted := range ca.PermittedDNSDomains {
			allowed = allowed || domainSubset(name, permitted)
		}
		if !allowed {
			return fmt.Errorf("DNS SAN %q is outside issuer permitted domains", name)
		}
		for _, excluded := range ca.ExcludedDNSDomains {
			// Be conservative for wildcards: refuse any overlap with an excluded
			// subtree, even when the wildcard itself passes a literal comparison.
			base := strings.TrimPrefix(name, "*.")
			if domainSubset(name, excluded) || strings.HasPrefix(name, "*.") && (domainSubset(base, excluded) || domainSubset(excluded, base)) {
				return fmt.Errorf("DNS SAN %q overlaps issuer excluded domain %q", name, excluded)
			}
		}
	}
	return nil
}

func loadCSR(path string) (*x509.CertificateRequest, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(b)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("expected a PEM certificate request")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}
	return csr, nil
}
