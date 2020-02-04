package cmd

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
)

var (
	caKeyPath, caCertPath string
)

func generatePrivateKey(size int, keyfile string) (*rsa.PrivateKey, error) {
	reader := rand.Reader
	key, err := rsa.GenerateKey(reader, size)
	if err != nil {
		return nil, err
	}
	f, err := os.Create(keyfile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var privateKey = &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(f, privateKey)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func signCert(template, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.PrivateKey, certfile string) error {
	b, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %s", err)
	}
	f, err := os.Create(certfile)
	if err != nil {
		return fmt.Errorf("failed to create certificate file %s: %v", certfile, err)
	}
	defer f.Close()
	certPem := &pem.Block{Type: "CERTIFICATE", Bytes: b}

	err = pem.Encode(f, certPem)
	if err != nil {
		return fmt.Errorf("failed to encode and write certificate file %s: %v", certfile, err)
	}
	return nil
}

// unfortunately, the golang library does not make it easy to parse DN
func parseSubject(subject string) (*pkix.Name, error) {
	var (
		err  error
		name pkix.Name
	)
	// the separator character could be escaped, so we cannot just blindly split on it
	separator := ','
	if len(subject) > 0 && subject[0] == '/' {
		separator = '/'
		subject = subject[1:]
	}
	// hold the current string
	current := make([]rune, 0)
	for _, c := range subject {
		if c != separator || (len(current) > 0 && current[len(current)-1] == '\\') {
			current = append(current, c)
			continue
		}
		// we are at a separator
		if err = populateName(&name, current); err != nil {
			return nil, err
		}
		// reset our current
		current = make([]rune, 0)
	}
	// do not miss anything at the end
	if len(current) > 0 {
		if err = populateName(&name, current); err != nil {
			return nil, err
		}
	}
	return &name, nil
}

func populateName(name *pkix.Name, rdn []rune) error {
	// split on the first =
	parts := strings.SplitN(string(rdn), "=", 2)
	switch parts[0] {
	case "C":
		name.Country = []string{parts[1]}
	case "O":
		name.Organization = []string{parts[1]}
	case "OU":
		name.OrganizationalUnit = []string{parts[1]}
	case "ST":
		name.Province = []string{parts[1]}
	case "L":
		name.Locality = []string{parts[1]}
	case "CN":
		name.CommonName = parts[1]
	default:
		return fmt.Errorf("unknown RDN: %s", string(rdn))
	}
	return nil
}

func loadAndSignCert(caCertPath, caKeyPath string, template *x509.Certificate, publicKey crypto.PublicKey, outCert string) error {
	// read the CA key and certificate
	caCert, err := tls.LoadX509KeyPair(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA cert/key: %v", err)
	}
	if len(caCert.Certificate) < 1 {
		return fmt.Errorf("unvalid CA certificate missing bytes")
	}
	caCertParsed, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse CA cert: %v", err)
	}

	err = signCert(template, caCertParsed, publicKey, caCert.PrivateKey, outCert)
	if err != nil {
		return fmt.Errorf("Failed to create certificate: %s", err)
	}
	return nil
}
