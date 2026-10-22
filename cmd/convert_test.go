package cmd

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"os"
	"path/filepath"
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
