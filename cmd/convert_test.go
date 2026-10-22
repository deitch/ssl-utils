package cmd

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

func TestModernPKCS12Output(t *testing.T) {
	d := t.TempDir()
	path := func(name string) string { return filepath.Join(d, name) }
	root := testRoot(t)
	pub, key := testKey(t)
	template := testTemplate(t, "Server")
	template.NotBefore = time.Now()
	der, err := root.issue(template, pub)
	if err != nil {
		t.Fatal(err)
	}
	for name, cert := range map[string][]byte{"root.pem": root.chain[0].Raw, "server.pem": der} {
		if err := certificateToPEMFile(cert, path(name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := privateKeyToPEMFile(key, path("server.key")); err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"bundle", "truststore"} {
		t.Run(kind, func(t *testing.T) {
			args := []string{"convert", "pkcs12", "write", path(kind + ".p12"), "--ca", path("root.pem"), "--password", "test-password"}
			if kind == "bundle" {
				args = append(args, "--key", path("server.key"), "--cert", path("server.pem"))
			}
			runCLI(t, false, args...)
			encoded, err := os.ReadFile(path(kind + ".p12"))
			if err != nil {
				t.Fatal(err)
			}
			// Check the emitted encryption identifiers, so a legacy encoder cannot
			// pass merely because the decoder also supports legacy encryption.
			for _, oid := range []asn1.ObjectIdentifier{
				{1, 2, 840, 113549, 1, 5, 13},     // PBES2
				{2, 16, 840, 1, 101, 3, 4, 1, 42}, // AES-256-CBC
			} {
				algorithm, err := asn1.Marshal(oid)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Contains(encoded, algorithm) {
					t.Fatalf("PKCS#12 output missing modern encryption algorithm %s", oid)
				}
			}
			if kind == "truststore" {
				certs, err := pkcs12.DecodeTrustStore(encoded, "test-password")
				if err != nil {
					t.Fatal(err)
				}
				if len(certs) != 1 || !bytes.Equal(certs[0].Raw, root.chain[0].Raw) {
					t.Fatal("trust store certificate changed during conversion")
				}
				if _, err := pkcs12.DecodeTrustStore(encoded, "wrong-password"); err == nil {
					t.Fatal("trust store accepted wrong password")
				}
				return
			}
			decodedKey, cert, chain, err := pkcs12.DecodeChain(encoded, "test-password")
			if err != nil {
				t.Fatal(err)
			}
			originalKey, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			roundTripKey, err := x509.MarshalPKCS8PrivateKey(decodedKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(originalKey, roundTripKey) || !bytes.Equal(cert.Raw, der) || len(chain) != 1 || !bytes.Equal(chain[0].Raw, root.chain[0].Raw) {
				t.Fatal("key, certificate, or chain changed during conversion")
			}
			if _, _, _, err := pkcs12.DecodeChain(encoded, "wrong-password"); err == nil {
				t.Fatal("key bundle accepted wrong password")
			}
		})
	}
}

func TestPKCS12ImportCLI(t *testing.T) {
	root := testRoot(t)
	i := testIntermediate(t, root, "Intermediate", "example.com", 0)
	pub, key := testKey(t)
	template := testTemplate(t, "Server")
	template.NotBefore, template.DNSNames = time.Now(), []string{"api.example.com"}
	der, err := i.issue(template, pub)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, password string
		encoder        *pkcs12.Encoder
	}{
		{"modern", "test-password", pkcs12.Modern},
		{"modern empty password", "", pkcs12.Modern},
		{"legacy input", "test-password", pkcs12.LegacyRC2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := t.TempDir()
			path := func(name string) string { return filepath.Join(d, name) }
			encoded, err := tc.encoder.Encode(key, leaf, i.chain, tc.password)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path("input.p12"), encoded, 0600); err != nil {
				t.Fatal(err)
			}
			runCLI(t, false, "convert", "pkcs12", "read", path("input.p12"), "--password", tc.password, "--key", path("output.key"), "--cert", path("output.pem"), "--ca", path("chain.pem"))
			assertPublicKey(t, readTestKey(t, path("output.key")).Public(), pub)
			if !bytes.Equal(readTestCert(t, path("output.pem")).Raw, leaf.Raw) {
				t.Fatal("leaf certificate changed during import")
			}
			b, err := os.ReadFile(path("chain.pem"))
			if err != nil {
				t.Fatal(err)
			}
			chain, err := parseCertificates(b)
			if err != nil || len(chain) != 2 {
				t.Fatalf("import lost CA ancestors: %v", err)
			}
			for n, cert := range chain {
				if !bytes.Equal(cert.Raw, i.chain[n].Raw) {
					t.Fatal("CA chain order or certificate changed")
				}
			}
			info, err := os.Stat(path("output.key"))
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("imported key permissions: %v, %v", info, err)
			}
		})
	}
}

func TestPKCS12ImportFailurePreservesOutputs(t *testing.T) {
	root := testRoot(t)
	encoded, err := pkcs12.Modern.Encode(root.key, root.chain[0], nil, "correct-password")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wrong password", "malformed", "tampered"} {
		t.Run(name, func(t *testing.T) {
			d := t.TempDir()
			path := func(name string) string { return filepath.Join(d, name) }
			data := append([]byte{}, encoded...)
			password := "correct-password"
			switch name {
			case "wrong password":
				password = "incorrect-password"
			case "malformed":
				data = []byte("not PKCS12")
			case "tampered":
				data[len(data)-1] ^= 1
			}
			if err := os.WriteFile(path("input.p12"), data, 0600); err != nil {
				t.Fatal(err)
			}
			for _, file := range []string{"key.pem", "cert.pem", "chain.pem"} {
				if err := os.WriteFile(path(file), []byte("existing output"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			out := runCLI(t, true, "convert", "pkcs12", "read", path("input.p12"), "--password", password, "--key", path("key.pem"), "--cert", path("cert.pem"), "--ca", path("chain.pem"))
			if !strings.Contains(out, "failed to decode file") || strings.Contains(out, "panic:") {
				t.Fatalf("expected a decoding error, got %s", out)
			}
			for _, file := range []string{"key.pem", "cert.pem", "chain.pem"} {
				b, err := os.ReadFile(path(file))
				if err != nil || string(b) != "existing output" {
					t.Fatalf("rejected PKCS12 import changed %s", file)
				}
			}
		})
	}
}
