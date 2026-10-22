package cmd

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestParseSubject(t *testing.T) {
	want := &pkix.Name{Country: []string{"US"}, Province: []string{"NY"}, Locality: []string{"New York"}, Organization: []string{"Example"}, OrganizationalUnit: []string{"Operations"}, CommonName: "server.example.com"}
	for _, subject := range []string{
		"C=US,ST=NY,L=New York,O=Example,OU=Operations,CN=server.example.com",
		"/C=US/ST=NY/L=New York/O=Example/OU=Operations/CN=server.example.com",
	} {
		got, err := parseSubject(subject)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Fatalf("parseSubject(%q) = %#v, %v; want %#v", subject, got, err, want)
		}
	}
	for _, subject := range []string{"CN", "CN=", "unknown=value", "CN=valid,,O=Example", "/CN=valid//O=Example"} {
		t.Run(subject, func(t *testing.T) {
			if _, err := parseSubject(subject); err == nil {
				t.Fatalf("accepted malformed subject %q", subject)
			}
		})
	}
	got, err := parseSubject("CN=name=with=equals")
	if err != nil || got.CommonName != "name=with=equals" {
		t.Fatalf("subject values containing '=' must be retained: %v, %v", got, err)
	}
}

func TestPrivateKeyFormats(t *testing.T) {
	for _, tc := range []struct {
		name string
		kind KeyType
	}{{"rsa", RSA}, {"ecdsa", ECDSA}, {"ed25519", Ed25519}} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "key.pem")
			key, pub, err := generateKeyPair(tc.kind, 2048, path)
			if err != nil {
				t.Fatal(err)
			}
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			block, _ := pem.Decode(b)
			if block == nil || block.Type != "PRIVATE KEY" {
				t.Fatal("generated key is not PKCS#8 PEM")
			}
			formats := map[string][]byte{"PKCS8": block.Bytes}
			switch k := key.(type) {
			case *rsa.PrivateKey:
				if k.N.BitLen() != 2048 {
					t.Fatal("RSA size flag ignored")
				}
				formats["PKCS1"] = x509.MarshalPKCS1PrivateKey(k)
			case *ecdsa.PrivateKey:
				if k.Curve.Params().Name != "P-256" {
					t.Fatal("unexpected ECDSA curve")
				}
				formats["SEC1"], err = x509.MarshalECPrivateKey(k)
				if err != nil {
					t.Fatal(err)
				}
			}
			for format, der := range formats {
				t.Run(format, func(t *testing.T) {
					parsed, err := parsePrivateKey(der)
					if err != nil {
						t.Fatal(err)
					}
					want, err := x509.MarshalPKCS8PrivateKey(key)
					if err != nil {
						t.Fatal(err)
					}
					got, err := x509.MarshalPKCS8PrivateKey(parsed)
					if err != nil {
						t.Fatal(err)
					}
					if !bytes.Equal(got, want) || !reflect.DeepEqual(parsed.(crypto.Signer).Public(), pub) {
						t.Fatal("key material changed during PEM/DER round trip")
					}
				})
			}
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm() != 0600 {
				t.Fatalf("private key permissions: %v, %v", info, err)
			}
		})
	}
	if _, _, err := generatePrivateKey(KeyType(-1), 2048); err == nil {
		t.Fatal("unknown key algorithm accepted")
	}
	if _, _, err := generatePrivateKey(RSA, 512); err == nil {
		t.Fatal("invalid RSA size accepted")
	}
	if _, err := parsePrivateKey([]byte("not a DER key")); err == nil {
		t.Fatal("malformed private key accepted")
	}
}

func TestOutputPathAliases(t *testing.T) {
	d := t.TempDir()
	input := filepath.Join(d, "issuer.key")
	content := []byte("must remain unchanged")
	if err := os.WriteFile(input, content, 0600); err != nil {
		t.Fatal(err)
	}
	hard, symlink := filepath.Join(d, "hardlink"), filepath.Join(d, "symlink")
	if err := os.Link(input, hard); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(input, symlink); err != nil {
		t.Fatal(err)
	}
	for _, output := range []string{input, filepath.Join(d, "nested", "..", "issuer.key"), hard, symlink} {
		if err := checkOutputPaths([]string{output}, []string{input}); err == nil {
			t.Fatalf("accepted alias of issuer input: %s", output)
		}
	}
	newPath := filepath.Join(d, "new.pem")
	if err := checkOutputPaths([]string{newPath, newPath}, nil); err == nil {
		t.Fatal("accepted identical output paths")
	}
	if err := checkOutputPaths([]string{newPath}, []string{input, ""}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(input)
	if err != nil || !bytes.Equal(got, content) {
		t.Fatal("path validation changed an input file")
	}
}
