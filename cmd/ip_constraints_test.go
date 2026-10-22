package cmd

import (
	"crypto/ed25519"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestIPConstraintsCLI(t *testing.T) {
	d := t.TempDir()
	path := func(name string) string { return filepath.Join(d, name) }
	root := testRoot(t)
	args := append([]string{"sign", "intermediate"}, testIssuerArgs(t, root)...)
	args = append(args, "--subject", "CN=IP Issuer", "--key", path("ca.key"), "--cert", path("ca.pem"), "--permit-name", "esi.bak,127.0.0.1", "--permit-name", "::1/128", "--exclude-name", "192.0.2.0/24")
	runCLI(t, false, args...)
	cert := readTestCert(t, path("ca.pem"))
	if !cert.PermittedDNSDomainsCritical || len(cert.PermittedIPRanges) != 2 || len(cert.ExcludedIPRanges) != 1 {
		t.Fatal("IP name constraints were not encoded")
	}
	out := runCLI(t, false, "read", path("ca.pem"))
	if !strings.Contains(out, "127.0.0.1/32") || !strings.Contains(out, "::1/128") {
		t.Fatalf("missing IP constraints in inspection: %s", out)
	}
	i := &issuer{chain: []*x509.Certificate{cert, root.chain[0]}, key: readTestKey(t, path("ca.key"))}
	issuerArgs := testIssuerArgs(t, i)
	for _, tc := range []struct {
		name, san string
		bad       bool
	}{
		{"DNS and IPv4", "vault.hq.esi.bak,127.0.0.1", false},
		{"IPv4 only", "127.0.0.1", false},
		{"DNS and IPv6", "vault.hq.esi.bak,::1", false},
		{"outside IPv4", "vault.hq.esi.bak,127.0.0.2", true},
		{"outside IPv6", "vault.hq.esi.bak,::2", true},
		{"outside DNS", "outside.test,127.0.0.1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"sign", "certificate"}, issuerArgs...)
			args = append(args, "--subject", "CN=vault.hq.esi.bak", "--san", tc.san, "--key", path("server.key"), "--cert", path("server.pem"))
			runCLI(t, tc.bad, args...)
			if !tc.bad {
				leaf := readTestCert(t, path("server.pem"))
				for _, name := range strings.Split(tc.san, ",") {
					opts := i.verifyOptions(x509.ExtKeyUsageServerAuth)
					opts.DNSName = name
					if _, err := leaf.Verify(opts); err != nil {
						t.Fatal(err)
					}
				}
			}
		})
	}
	// CSR issuance must enforce the same policy as subject issuance.
	pub, key := testKey(t)
	csrPath := path("request.pem")
	for _, address := range []string{"127.0.0.1", "127.0.0.2"} {
		if err := saveCSR(&x509.CertificateRequest{DNSNames: []string{"vault.hq.esi.bak"}, IPAddresses: []net.IP{net.ParseIP(address)}}, key, csrPath); err != nil {
			t.Fatal(err)
		}
		args := append([]string{"sign", "certificate"}, issuerArgs...)
		args = append(args, "--csr", csrPath, "--cert", path("csr.pem"), "--approve")
		runCLI(t, address != "127.0.0.1", args...)
	}
	// Clients reject an outside IP even when a different signing program ignores
	// our CLI checks and signs the certificate directly.
	rogue := testTemplate(t, "Outside IP")
	rogue.NotBefore, rogue.IPAddresses = time.Now(), []net.IP{net.ParseIP("127.0.0.2")}
	issued := testCertificate(t, rogue, cert, pub, i.key.(ed25519.PrivateKey))
	if _, err := issued.Verify(i.verifyOptions(x509.ExtKeyUsageServerAuth)); err == nil {
		t.Fatal("chain verification ignored the IP constraint")
	}
}

func TestIPDelegationAndExclusions(t *testing.T) {
	root := testRoot(t)
	parent := testIntermediate(t, root, "Parent", "example.com", 1)
	p := *parent.chain[0]
	var err error
	p.PermittedIPRanges, err = parseIPRanges([]string{"10.0.0.0/8", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	p.ExcludedIPRanges, err = parseIPRanges([]string{"10.1.0.0/16"})
	if err != nil {
		t.Fatal(err)
	}
	parent.chain[0] = testCertificate(t, &p, root.chain[0], p.PublicKey.(ed25519.PublicKey), root.key.(ed25519.PrivateKey))
	for _, tc := range []struct {
		cidr string
		bad  bool
	}{
		{"10.0.0.0/9", false},
		{"10.2.0.0/16", false},
		{"2001:db8:1::/48", false},
		{"10.0.0.0/7", true},
		{"10.1.0.0/16", true},
		{"192.0.2.0/24", true},
		{"2001::/16", true},
	} {
		t.Run(tc.cidr, func(t *testing.T) {
			c := testTemplate(t, "Child")
			c.NotBefore, c.IsCA, c.KeyUsage = time.Now(), true, x509.KeyUsageCertSign
			c.MaxPathLenZero, c.PermittedDNSDomainsCritical = true, true
			c.PermittedDNSDomains = []string{"example.com"}
			c.PermittedIPRanges, err = parseIPRanges([]string{tc.cidr})
			if err != nil {
				t.Fatal(err)
			}
			pub, key := testKey(t)
			der, err := parent.issue(c, pub)
			if (err != nil) != tc.bad {
				t.Fatalf("delegation of %s: %v", tc.cidr, err)
			}
			if tc.bad {
				return
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			if len(cert.ExcludedIPRanges) != 1 || cert.ExcludedIPRanges[0].String() != "10.1.0.0/16" {
				t.Fatal("ancestor IP exclusion was lost")
			}
			child := &issuer{chain: append([]*x509.Certificate{cert}, parent.chain...), key: key}
			leaf := testTemplate(t, "Excluded IP")
			leaf.NotBefore, leaf.IPAddresses = time.Now(), []net.IP{net.ParseIP("10.1.2.3")}
			if _, err := child.issue(leaf, pub); err == nil {
				t.Fatal("excluded IP accepted")
			}
		})
	}
	// A DNS-only intermediate must not gain IP privileges through delegation.
	dnsOnly := testIntermediate(t, root, "DNS Only", "example.com", 1)
	p.Subject.CommonName, p.RawSubject = "New Child", nil
	p.MaxPathLen, p.MaxPathLenZero = 0, true
	p.NotBefore = time.Now()
	if _, err := dnsOnly.issue(&p, p.PublicKey); err == nil {
		t.Fatal("DNS-only ancestor allowed new IP delegation")
	}
}

func TestInvalidNameConstraintsCLI(t *testing.T) {
	issuerArgs := testIssuerArgs(t, testRoot(t))
	for _, value := range []string{"bad/cidr", "127.0.0.1/33", "::1/129", "::ffff:127.0.0.1/128", ""} {
		for _, flag := range []string{"--permit-name", "--exclude-name"} {
			t.Run(flag+value, func(t *testing.T) {
				d := t.TempDir()
				keyPath, certPath := filepath.Join(d, "key.pem"), filepath.Join(d, "cert.pem")
				args := append([]string{"sign", "intermediate"}, issuerArgs...)
				args = append(args, "--subject", "CN=Invalid", "--key", keyPath, "--cert", certPath, "--permit-name", "example.com", flag, value)
				// An explicitly empty IP flag denotes no ranges, just like the DNS
				// slice flags. Other malformed values must fail before output.
				if value == "" {
					runCLI(t, false, args...)
					return
				}
				runCLI(t, true, args...)
				for _, file := range []string{keyPath, certPath} {
					if _, err := os.Stat(file); !os.IsNotExist(err) {
						t.Fatal("invalid CIDR wrote output")
					}
				}
			})
		}
	}
}

func TestMixedNameConstraints(t *testing.T) {
	domains, ranges, err := parseNameConstraints([]string{"esi.bak", " .hq.esi.bak ", "127.0.0.1", "::1", "10.2.3.4/24", "2001:db8::/32"})
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 || domains[0] != "esi.bak" || domains[1] != ".hq.esi.bak" || len(ranges) != 4 {
		t.Fatalf("mixed names were not separated correctly: %v %v", domains, ranges)
	}
	for n, want := range []string{"127.0.0.1/32", "::1/128", "10.2.3.0/24", "2001:db8::/32"} {
		if ranges[n].String() != want {
			t.Fatalf("IP constraint = %s, want %s", ranges[n], want)
		}
	}
}

func TestUnifiedNameConstraintFlags(t *testing.T) {
	out := runCLI(t, false, "sign", "intermediate", "--help")
	for _, flag := range []string{"--permit-name", "--exclude-name"} {
		if !strings.Contains(out, flag) {
			t.Fatalf("missing unified flag in help: %s", out)
		}
	}
	for _, flag := range []string{"--permit-dns", "--permit-ip", "--exclude-dns", "--exclude-ip"} {
		if strings.Contains(out, flag) {
			t.Fatalf("old flag still present in help: %s", out)
		}
		if rejected := runCLI(t, true, "sign", "intermediate", flag, "example.com"); !strings.Contains(rejected, "unknown flag") {
			t.Fatalf("old flag was not rejected: %s", rejected)
		}
	}
}
