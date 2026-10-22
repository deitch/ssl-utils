package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadIssuerRejectsInvalidPEMChains(t *testing.T) {
	root := testRoot(t)
	i := testIntermediate(t, root, "Intermediate", "example.com", 0)
	for _, name := range []string{"mismatched key", "wrong root", "missing root", "empty ancestors", "malformed ancestors", "duplicate ancestors", "expired", "future", "not CA", "no signing usage", "bad signature", "unknown critical extension", "exceeded path length"} {
		t.Run(name, func(t *testing.T) {
			d := t.TempDir()
			certPath, keyPath, chainPath := filepath.Join(d, "ca.pem"), filepath.Join(d, "ca.key"), filepath.Join(d, "chain.pem")
			cert, ancestor, key := i.chain[0], root.chain[0], i.key
			template := *cert
			switch name {
			case "mismatched key":
				_, key = testKey(t)
			case "wrong root":
				ancestor = testRoot(t).chain[0]
			case "expired":
				template.NotBefore, template.NotAfter = time.Now().Add(-2*time.Hour), time.Now().Add(-time.Hour)
			case "future":
				template.NotBefore, template.NotAfter = time.Now().Add(time.Hour), time.Now().Add(2*time.Hour)
			case "not CA":
				template.IsCA, template.MaxPathLen, template.MaxPathLenZero = false, -1, false
			case "no signing usage":
				template.KeyUsage = x509.KeyUsageDigitalSignature
			case "unknown critical extension":
				template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{1, 2, 3, 4, 5}, Critical: true, Value: []byte{5, 0}}}
			case "exceeded path length":
				rootTemplate := *ancestor
				rootTemplate.MaxPathLen, rootTemplate.MaxPathLenZero = 0, true
				ancestor = testCertificate(t, &rootTemplate, &rootTemplate, root.chain[0].PublicKey.(ed25519.PublicKey), root.key.(ed25519.PrivateKey))
			}
			cert = testCertificate(t, &template, root.chain[0], i.chain[0].PublicKey.(ed25519.PublicKey), root.key.(ed25519.PrivateKey))
			der := append([]byte{}, cert.Raw...)
			if name == "bad signature" {
				der[len(der)-1] ^= 1
			}
			if err := certificateToPEMFile(der, certPath); err != nil {
				t.Fatal(err)
			}
			if err := privateKeyToPEMFile(key, keyPath); err != nil {
				t.Fatal(err)
			}
			chain := [][]byte{ancestor.Raw}
			if name == "duplicate ancestors" {
				chain = append(chain, ancestor.Raw)
			}
			if err := certificatesToPEMFile(chain, chainPath); err != nil {
				t.Fatal(err)
			}
			switch name {
			case "missing root":
				chainPath = ""
			case "empty ancestors", "malformed ancestors":
				var data []byte
				if name == "malformed ancestors" {
					data = []byte("invalid PEM")
				}
				if err := os.WriteFile(chainPath, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := loadIssuer(certPath, keyPath, chainPath); err == nil {
				t.Fatal("invalid serialized issuer accepted")
			}
		})
	}
}

func TestCSRApprovalCLI(t *testing.T) {
	issuerArgs := testIssuerArgs(t, testRoot(t))
	for _, command := range []string{"certificate", "intermediate"} {
		for _, tc := range []struct {
			name, input string
			bad         bool
		}{{"yes", "y\n", false}, {"uppercase", "Y\n", false}, {"no", "n\n", true}, {"blank", "\n", true}, {"EOF", "", true}} {
			t.Run(command+"/"+tc.name, func(t *testing.T) {
				d := t.TempDir()
				request, output := filepath.Join(d, "request.pem"), filepath.Join(d, "issued.pem")
				writeTestCSR(t, request, []string{"api.example.com"}, false)
				before, err := os.ReadFile(request)
				if err != nil {
					t.Fatal(err)
				}
				args := append([]string{"sign", command}, issuerArgs...)
				args = append(args, "--csr", request, "--cert", output)
				if command == "intermediate" {
					args = append(args, "--permit-name", "example.com")
				}
				out := runCLIWithInput(t, tc.bad, tc.input, args...)
				if !strings.Contains(out, "Approve certificate for CN=Requested") {
					t.Fatalf("missing approval prompt: %s", out)
				}
				if tc.bad {
					if _, err := os.Stat(output); !os.IsNotExist(err) {
						t.Fatal("unapproved CSR wrote a certificate")
					}
				} else {
					csr, err := loadCSR(request)
					if err != nil {
						t.Fatal(err)
					}
					assertPublicKey(t, readTestCert(t, output).PublicKey, csr.PublicKey)
				}
				after, err := os.ReadFile(request)
				if err != nil || !bytes.Equal(before, after) {
					t.Fatal("approval changed the CSR input")
				}
			})
		}
	}
}

func TestCSRRequestedPrivilegesAreNotTrusted(t *testing.T) {
	d := t.TempDir()
	pub, key := testKey(t)
	requestedCA, err := asn1.Marshal(struct {
		IsCA       bool
		MaxPathLen int
	}{true, 10})
	if err != nil {
		t.Fatal(err)
	}
	csr := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "Requested CA"},
		ExtraExtensions: []pkix.Extension{{
			Id: asn1.ObjectIdentifier{2, 5, 29, 19}, Critical: true, Value: requestedCA,
		}},
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, csr, key)
	if err != nil {
		t.Fatal(err)
	}
	request := filepath.Join(d, "request.pem")
	if err := os.WriteFile(request, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	issuerArgs := testIssuerArgs(t, testRoot(t))
	for _, command := range []string{"certificate", "intermediate"} {
		output := filepath.Join(d, command+".pem")
		args := append([]string{"sign", command}, issuerArgs...)
		args = append(args, "--csr", request, "--cert", output, "--approve")
		if command == "intermediate" {
			args = append(args, "--permit-name", "example.com")
		}
		runCLI(t, false, args...)
		cert := readTestCert(t, output)
		assertPublicKey(t, cert.PublicKey, pub)
		if command == "certificate" {
			if cert.IsCA || cert.KeyUsage&x509.KeyUsageCertSign != 0 {
				t.Fatal("CSR escalated leaf privileges to CA")
			}
		} else if !cert.IsCA || !cert.MaxPathLenZero || len(cert.PermittedDNSDomains) != 1 || cert.PermittedDNSDomains[0] != "example.com" {
			t.Fatal("CSR overrode issuer-selected intermediate policy")
		}
	}
}

func TestConstrainedSigningFailurePreservesOutputs(t *testing.T) {
	i := testIntermediate(t, testRoot(t), "Intermediate", "example.com", 0)
	issuerArgs := testIssuerArgs(t, i)
	for _, mode := range []string{"subject", "CSR"} {
		t.Run(mode, func(t *testing.T) {
			d := t.TempDir()
			keyPath, certPath := filepath.Join(d, "existing.key"), filepath.Join(d, "existing.pem")
			for _, file := range []string{keyPath, certPath} {
				if err := os.WriteFile(file, []byte("existing output"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			args := append([]string{"sign", "certificate"}, issuerArgs...)
			args = append(args, "--cert", certPath)
			if mode == "subject" {
				args = append(args, "--subject", "CN=Outside", "--san", "outside.test", "--key", keyPath)
			} else {
				request := filepath.Join(d, "request.pem")
				writeTestCSR(t, request, []string{"outside.test"}, false)
				args = append(args, "--csr", request, "--approve")
			}
			if out := runCLI(t, true, args...); !strings.Contains(out, "outside issuer permitted domains") {
				t.Fatalf("expected domain-policy rejection: %s", out)
			}
			for _, file := range []string{keyPath, certPath} {
				b, err := os.ReadFile(file)
				if err != nil || string(b) != "existing output" {
					t.Fatalf("policy rejection changed %s", file)
				}
			}
		})
	}
}

func TestLeafExpiryCappedByAncestor(t *testing.T) {
	root := testRoot(t)
	rootTemplate := *root.chain[0]
	rootTemplate.NotAfter = time.Now().Add(2 * time.Hour)
	root.chain[0] = testCertificate(t, &rootTemplate, &rootTemplate, rootTemplate.PublicKey.(ed25519.PublicKey), root.key.(ed25519.PrivateKey))
	pub, key := testKey(t)
	intermediateTemplate := testTemplate(t, "Intermediate")
	intermediateTemplate.IsCA, intermediateTemplate.KeyUsage = true, x509.KeyUsageCertSign
	intermediateTemplate.NotAfter = time.Now().Add(24 * time.Hour)
	// An externally issued intermediate can outlive its root. Even then the
	// CLI must cap new leaves at the earliest expiry, including ancestors.
	intermediate := testCertificate(t, intermediateTemplate, root.chain[0], pub, root.key.(ed25519.PrivateKey))
	i := &issuer{chain: []*x509.Certificate{intermediate, root.chain[0]}, key: key}
	leaf := testTemplate(t, "Leaf")
	leaf.NotBefore = time.Now()
	leafPub, _ := testKey(t)
	der, err := i.issue(leaf, leafPub)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	if !cert.NotAfter.Equal(root.chain[0].NotAfter) {
		t.Fatal("leaf validity was not capped at root expiry")
	}
}

func TestCertificateTemplateBoundsAndSerials(t *testing.T) {
	maxDays := int((1<<63 - 1) / int64(24*time.Hour))
	for _, days := range []int{0, -1, maxDays + 1} {
		if _, err := newCertificateTemplate(pkix.Name{CommonName: "Invalid"}, days); err == nil {
			t.Fatalf("accepted invalid validity duration: %d days", days)
		}
	}
	a, err := newCertificateTemplate(pkix.Name{CommonName: "First"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	b, err := newCertificateTemplate(pkix.Name{CommonName: "Second"}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if a.SerialNumber.Sign() <= 0 || b.SerialNumber.Sign() <= 0 || a.SerialNumber.Cmp(b.SerialNumber) == 0 {
		t.Fatal("certificate serials must be positive and distinct")
	}
}
