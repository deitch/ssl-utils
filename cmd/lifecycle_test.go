package cmd

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func readTestKey(t *testing.T, path string) crypto.Signer {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatal("missing PEM key")
	}
	key, err := parsePrivateKey(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		t.Fatal("key cannot sign")
	}
	return signer
}

func assertPublicKey(t *testing.T, key crypto.PublicKey, want crypto.PublicKey) {
	t.Helper()
	gotDER, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	wantDER, err := x509.MarshalPKIXPublicKey(want)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotDER, wantDER) {
		t.Fatal("public key does not match private key or request")
	}
}

func TestRootAndLeafKeyAlgorithmsCLI(t *testing.T) {
	for _, algorithm := range []string{"rsa", "ecdsa", "ed25519"} {
		t.Run(algorithm, func(t *testing.T) {
			d := t.TempDir()
			path := func(name string) string { return filepath.Join(d, name) }
			runCLI(t, false, "init", "--subject", "/C=US/O=Example/CN=Root", "--ca-key", path("root.key"), "--ca-cert", path("root.pem"), "--key-type", algorithm, "--key-size", "2048", "--days", "2")
			root := readTestCert(t, path("root.pem"))
			if !root.IsCA || !root.BasicConstraintsValid || root.KeyUsage&x509.KeyUsageCertSign == 0 || root.NotAfter.Sub(root.NotBefore) != 48*time.Hour {
				t.Fatal("generated root has incorrect CA properties or validity")
			}
			if err := root.CheckSignatureFrom(root); err != nil {
				t.Fatal(err)
			}
			assertPublicKey(t, root.PublicKey, readTestKey(t, path("root.key")).Public())
			runCLI(t, false, "sign", "certificate", "--ca-key", path("root.key"), "--ca-cert", path("root.pem"), "--subject", "CN=api.example.com", "--san", "api.example.com,127.0.0.1,::1", "--key", path("server.key"), "--cert", path("server.pem"), "--key-type", algorithm, "--key-size", "2048", "--days", "1")
			leaf := readTestCert(t, path("server.pem"))
			if leaf.IsCA || leaf.KeyUsage&x509.KeyUsageCertSign != 0 || len(leaf.DNSNames) != 1 || len(leaf.IPAddresses) != 2 || leaf.NotAfter.Sub(leaf.NotBefore) != 24*time.Hour {
				t.Fatal("generated leaf has incorrect privileges, SANs, or validity")
			}
			assertPublicKey(t, leaf.PublicKey, readTestKey(t, path("server.key")).Public())
			roots := x509.NewCertPool()
			roots.AddCert(root)
			for _, name := range []string{"api.example.com", "127.0.0.1", "::1"} {
				for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
					if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: name, KeyUsages: []x509.ExtKeyUsage{usage}}); err != nil {
						t.Fatal(err)
					}
				}
			}
			out := runCLI(t, false, "read", path("server.key"))
			if !strings.Contains(out, strings.ToUpper(algorithm)+" PRIVATE KEY") {
				t.Fatalf("incorrect key inspection: %s", out)
			}
		})
	}
}

func TestCSRGenerationAndSigningCLI(t *testing.T) {
	d := t.TempDir()
	path := func(name string) string { return filepath.Join(d, name) }
	runCLI(t, false, "csr", "--subject", "C=US,O=Example,CN=api.example.com", "--san", "api.example.com,127.0.0.1,::1", "--key", path("server.key"), "--csr", path("request.pem"))
	csr, err := loadCSR(path("request.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if csr.Subject.CommonName != "api.example.com" || len(csr.DNSNames) != 1 || len(csr.IPAddresses) != 2 {
		t.Fatal("CSR subject or SANs did not survive generation")
	}
	assertPublicKey(t, csr.PublicKey, readTestKey(t, path("server.key")).Public())
	root := testRoot(t)
	args := append([]string{"sign", "certificate"}, testIssuerArgs(t, root)...)
	args = append(args, "--csr", path("request.pem"), "--cert", path("server.pem"), "--approve")
	runCLI(t, false, args...)
	cert := readTestCert(t, path("server.pem"))
	assertPublicKey(t, cert.PublicKey, csr.PublicKey)
	if cert.Subject.String() != csr.Subject.String() || len(cert.IPAddresses) != len(csr.IPAddresses) || !cert.IPAddresses[0].Equal(csr.IPAddresses[0]) || !cert.IPAddresses[1].Equal(csr.IPAddresses[1]) {
		t.Fatal("CSR identity changed during issuance")
	}
	if _, err := cert.Verify(root.verifyOptions(x509.ExtKeyUsageServerAuth)); err != nil {
		t.Fatal(err)
	}
	out := runCLI(t, false, "read", path("request.pem"))
	for _, value := range []string{"CERTIFICATE REQUEST", "CN=api.example.com", "127.0.0.1", "::1"} {
		if !strings.Contains(out, value) {
			t.Fatalf("CSR inspection missing %q: %s", value, out)
		}
	}
	out = runCLI(t, false, "read", path("server.pem"))
	for _, value := range []string{"CERTIFICATE", "Issuer: CN=Root", "CA: false", "ServerAuth", "api.example.com"} {
		if !strings.Contains(out, value) {
			t.Fatalf("certificate inspection missing %q: %s", value, out)
		}
	}
}

func TestReadRejectsInvalidFilesCLI(t *testing.T) {
	for _, tc := range []struct {
		name, label, contents, message string
	}{
		{"not PEM", "", "not a PEM file", "no valid PEM"},
		{"certificate", "CERTIFICATE", "not DER", "failed to parse certificate"},
		{"key", "PRIVATE KEY", "not DER", "failed to parse private key"},
		{"request", "CERTIFICATE REQUEST", "not DER", "unable to parse certificate signing request"},
		{"unsupported block", "PUBLIC KEY", "not DER", "is not a key, certificate or signing request"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "invalid.pem")
			data := []byte(tc.contents)
			if tc.label != "" {
				data = pem.EncodeToMemory(&pem.Block{Type: tc.label, Bytes: data})
			}
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			out := runCLI(t, true, "read", path)
			if !strings.Contains(out, tc.message) || strings.Contains(out, "panic:") {
				t.Fatalf("expected a parse error, got: %s", out)
			}
		})
	}
	runCLI(t, true, "read")
	runCLI(t, true, "read", filepath.Join(t.TempDir(), "missing.pem"))
}
