package cmd

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var (
	caKeyPath, caCertPath, saNames string
)

type KeyType int

const (
	RSA KeyType = iota
	Ed25519
	ECDSA
)

func generateKeyPair(keyType KeyType, size int, keyfile string) (crypto.PrivateKey, crypto.PublicKey, error) {
	privateKey, publicKey, err := generatePrivateKey(keyType, size)
	if err != nil {
		return nil, nil, err
	}
	if err := privateKeyToPEMFile(privateKey, keyfile); err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func generatePrivateKey(keyType KeyType, size int) (crypto.PrivateKey, crypto.PublicKey, error) {
	var (
		privateKey, publicKey interface{}
		err                   error
	)
	reader := rand.Reader
	switch keyType {
	case RSA:
		rsaPrivateKey, perr := rsa.GenerateKey(reader, size)
		privateKey = rsaPrivateKey
		err = perr
		if perr == nil {
			publicKey = rsaPrivateKey.Public()
		}
	case Ed25519:
		publicKey, privateKey, err = ed25519.GenerateKey(reader)
	case ECDSA:
		curve := elliptic.P256()
		ecdsaPrivateKey, perr := ecdsa.GenerateKey(curve, reader)
		privateKey = ecdsaPrivateKey
		err = perr
		if perr == nil {
			publicKey = ecdsaPrivateKey.Public()
		}
	default:
		return nil, nil, fmt.Errorf("unknown key type: %v", keyType)
	}

	if err != nil {
		return nil, nil, err
	}
	return privateKey, publicKey, nil
}

func privateKeyToPEMFile(privateKey interface{}, keyfile string) error {
	b, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return err
	}
	privateKeyPem := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}
	f, err := os.OpenFile(keyfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	return pem.Encode(f, privateKeyPem)
}

func certificateToPEMFile(b []byte, certfile string) error {
	return certificatesToPEMFile([][]byte{b}, certfile)
}

func certificatesToPEMFile(bs [][]byte, certfile string) error {
	f, err := os.Create(certfile)
	if err != nil {
		return fmt.Errorf("failed to create certificate file %s: %v", certfile, err)
	}
	defer func() { _ = f.Close() }()
	for _, b := range bs {
		certPem := &pem.Block{Type: "CERTIFICATE", Bytes: b}
		err := pem.Encode(f, certPem)
		if err != nil {
			return err
		}
	}
	return nil
}

func signCert(template, parent *x509.Certificate, pub crypto.PublicKey, priv crypto.PrivateKey, certfile string) error {
	b, err := x509.CreateCertificate(rand.Reader, template, parent, pub, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %s", err)
	}
	return certificateToPEMFile(b, certfile)
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
	if len(parts) != 2 || parts[1] == "" {
		return fmt.Errorf("invalid RDN: %s", string(rdn))
	}
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
	issuer, err := loadIssuer(caCertPath, caKeyPath, chainPath)
	if err != nil {
		return err
	}
	b, err := issuer.issue(template, publicKey)
	if err != nil {
		return err
	}
	return certificateToPEMFile(b, outCert)
}

func saveCSR(csr *x509.CertificateRequest, key crypto.PrivateKey, filePath string) error {
	b, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		return err
	}
	f, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	pemFormat := &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: b}
	err = pem.Encode(f, pemFormat)
	if err != nil {
		return err
	}
	return nil
}

func validateKeyType(cmd *cobra.Command, args []string) {
	switch keyTypeName {
	case "rsa":
		keyType = RSA
	case "ecdsa":
		keyType = ECDSA
	case "ed25519":
		keyType = Ed25519
	default:
		fmt.Fprintf(os.Stderr, "unknown key type: %s", keyTypeName)
		os.Exit(1)
	}
}

func writeNewPrivateKey(key crypto.PrivateKey, path string) error {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: b}); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(path)
		return err
	}
	return nil
}

func writeCertificate(f *os.File, der []byte) error {
	return pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// Check both path spelling and existing file identity (including symlinks and
// hard links) before any signing output can overwrite issuer material.
func checkOutputPaths(outputs, inputs []string) error {
	for n, output := range outputs {
		outputPath, err := filepath.Abs(output)
		if err != nil {
			return err
		}
		outputInfo, _ := os.Stat(output)
		for _, input := range append(append([]string{}, inputs...), outputs[:n]...) {
			if input == "" {
				continue
			}
			inputPath, err := filepath.Abs(input)
			if err != nil {
				return err
			}
			inputInfo, _ := os.Stat(input)
			if outputPath == inputPath || outputInfo != nil && inputInfo != nil && os.SameFile(outputInfo, inputInfo) {
				return fmt.Errorf("output %q must differ from inputs and other outputs", output)
			}
		}
	}
	return nil
}
