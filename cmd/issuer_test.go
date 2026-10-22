package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testTemplate(t *testing.T, name string) *x509.Certificate {
	t.Helper()
	c, err := newCertificateTemplate(pkix.Name{CommonName: name}, 30)
	if err != nil {
		t.Fatal(err)
	}
	c.NotBefore = time.Now().Add(-time.Minute)
	return c
}

func testKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, key
}

func testCertificate(t *testing.T, template, parent *x509.Certificate, pub ed25519.PublicKey, key ed25519.PrivateKey) *x509.Certificate {
	t.Helper()
	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, key)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func testRoot(t *testing.T) *issuer {
	t.Helper()
	pub, key := testKey(t)
	c := testTemplate(t, "Root")
	c.IsCA, c.KeyUsage = true, x509.KeyUsageCertSign
	return &issuer{chain: []*x509.Certificate{testCertificate(t, c, c, pub, key)}, key: key}
}

func testIntermediate(t *testing.T, parent *issuer, name, domain string, depth int) *issuer {
	t.Helper()
	pub, key := testKey(t)
	c := testTemplate(t, name)
	c.IsCA, c.KeyUsage = true, x509.KeyUsageCertSign
	c.MaxPathLen, c.MaxPathLenZero = depth, depth == 0
	c.PermittedDNSDomainsCritical = true
	c.PermittedDNSDomains = []string{domain}
	// issue() requires the child's start to be within the issuer validity.
	c.NotBefore = time.Now()
	der, err := parent.issue(c, pub)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return &issuer{chain: append([]*x509.Certificate{cert}, parent.chain...), key: key}
}

func TestConstrainedIssuance(t *testing.T) {
	root := testRoot(t)
	i := testIntermediate(t, root, "Issuing CA", "example.com", 0)
	if !i.chain[0].IsCA || !i.chain[0].PermittedDNSDomainsCritical || !i.chain[0].MaxPathLenZero {
		t.Fatal("intermediate is missing critical constraints")
	}
	for _, tc := range []struct {
		name string
		dns  []string
		bad  bool
	}{
		{"apex", []string{"example.com"}, false},
		{"subdomain", []string{"www.example.com"}, false},
		{"case", []string{"WWW.EXAMPLE.COM"}, false},
		{"wildcard", []string{"*.example.com"}, false},
		{"outside", []string{"outside.test"}, true},
		{"suffix attack", []string{"badexample.com"}, true},
		{"mixed", []string{"www.example.com", "outside.test"}, true},
		{"no SAN", nil, true},
		{"trailing dot", []string{"www.example.com."}, true},
		{"malformed", []string{"x..example.com"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, _ := testKey(t)
			c := testTemplate(t, "Leaf")
			c.NotBefore, c.DNSNames = time.Now(), tc.dns
			c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
			der, err := i.issue(c, pub)
			if (err != nil) != tc.bad {
				t.Fatalf("issue error = %v, want rejection %v", err, tc.bad)
			}
			if err == nil {
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := cert.Verify(i.verifyOptions(x509.ExtKeyUsageServerAuth)); err != nil {
					t.Fatal(err)
				}
				if cert.NotAfter.After(i.chain[0].NotAfter) {
					t.Fatal("leaf outlives issuer")
				}
			}
		})
	}
	for _, kind := range []string{"IP", "email", "URI"} {
		t.Run(kind, func(t *testing.T) {
			pub, _ := testKey(t)
			c := testTemplate(t, "Leaf")
			c.NotBefore, c.DNSNames = time.Now(), []string{"www.example.com"}
			switch kind {
			case "IP":
				c.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
			case "email":
				c.EmailAddresses = []string{"user@example.com"}
			case "URI":
				c.URIs = []*url.URL{{Scheme: "https", Host: "example.com"}}
			}
			if _, err := i.issue(c, pub); err == nil {
				t.Fatal("non-DNS identity accepted")
			}
		})
	}
	// Demonstrate that the extension protects clients even if a signer bypasses
	// our issuance checks and signs an outside-domain certificate directly.
	pub, _ := testKey(t)
	c := testTemplate(t, "Outside")
	c.NotBefore, c.DNSNames = time.Now(), []string{"outside.test"}
	rogue := testCertificate(t, c, i.chain[0], pub, i.key.(ed25519.PrivateKey))
	if _, err := rogue.Verify(i.verifyOptions(x509.ExtKeyUsageServerAuth)); err == nil {
		t.Fatal("chain verification ignored domain constraints")
	}
}

func TestDelegationAndAncestorConstraints(t *testing.T) {
	root := testRoot(t)
	parent := testIntermediate(t, root, "Parent", ".example.com", 1)
	// Add a valid, signed parent exclusion, then ensure it survives delegation.
	pub := parent.chain[0].PublicKey.(ed25519.PublicKey)
	p := *parent.chain[0]
	p.ExcludedDNSDomains = []string{"secret.team.example.com"}
	parent.chain[0] = testCertificate(t, &p, root.chain[0], pub, root.key.(ed25519.PrivateKey))
	child := testIntermediate(t, parent, "Child", "team.example.com", 0)
	if !containsDomain(child.chain[0].ExcludedDNSDomains, "secret.team.example.com") {
		t.Fatal("ancestor exclusion was not inherited")
	}
	for _, name := range []string{"secret.team.example.com", "*.team.example.com", "outside.example.com"} {
		c := testTemplate(t, "Leaf")
		c.NotBefore, c.DNSNames = time.Now(), []string{name}
		pub, _ := testKey(t)
		if _, err := child.issue(c, pub); err == nil {
			t.Fatalf("accepted forbidden name %q", name)
		}
	}
	for _, tc := range []struct {
		name, domain string
		parent       *issuer
		depth        int
	}{
		{"zero depth", "team.example.com", child, 0},
		{"too much depth", "team.example.com", parent, 1},
		{"widen subtree", "example.com", parent, 0},
		{"excluded subtree", "secret.team.example.com", parent, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := testTemplate(t, "Forbidden CA")
			c.NotBefore, c.IsCA, c.KeyUsage = time.Now(), true, x509.KeyUsageCertSign
			c.MaxPathLen, c.MaxPathLenZero = tc.depth, tc.depth == 0
			c.PermittedDNSDomains = []string{tc.domain}
			pub, _ := testKey(t)
			if _, err := tc.parent.issue(c, pub); err == nil {
				t.Fatal("invalid delegation accepted")
			}
		})
	}
	// A child's own permissions cannot erase an ancestor's exclusion.
	unchecked := *child.chain[0]
	unchecked.ExcludedDNSDomains = nil
	unchecked.PermittedDNSDomains = []string{"example.com"}
	child.chain[0] = testCertificate(t, &unchecked, parent.chain[0], child.chain[0].PublicKey.(ed25519.PublicKey), parent.key.(ed25519.PrivateKey))
	c := testTemplate(t, "Leaf")
	c.NotBefore, c.DNSNames = time.Now(), []string{"secret.team.example.com"}
	if _, err := child.issue(c, pub); err == nil {
		t.Fatal("ancestor exclusion bypassed")
	}
}

func TestIssuerValidation(t *testing.T) {
	root := testRoot(t)
	i := testIntermediate(t, root, "Intermediate", "example.com", 0)
	for _, tc := range []struct {
		name string
		edit func(*issuer)
	}{
		{"missing root", func(i *issuer) { i.chain = i.chain[:1] }},
		{"wrong root", func(i *issuer) { i.chain[1] = testRoot(t).chain[0] }},
		{"wrong order", func(i *issuer) { i.chain[0], i.chain[1] = i.chain[1], i.chain[0] }},
		{"expired", func(i *issuer) { i.chain[0].NotAfter = time.Now().Add(-time.Hour) }},
		{"future", func(i *issuer) { i.chain[0].NotBefore = time.Now().Add(time.Hour) }},
		{"not CA", func(i *issuer) { i.chain[0].IsCA = false }},
		{"no signing usage", func(i *issuer) { i.chain[0].KeyUsage = x509.KeyUsageDigitalSignature }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			copyIssuer := &issuer{key: i.key}
			for _, c := range i.chain {
				copyCert := *c
				copyIssuer.chain = append(copyIssuer.chain, &copyCert)
			}
			tc.edit(copyIssuer)
			if err := copyIssuer.validate(); err == nil {
				t.Fatal("invalid issuer accepted")
			}
		})
	}
}

func TestSubdomainOnlyAndIssuerEKU(t *testing.T) {
	root := testRoot(t)
	i := testIntermediate(t, root, "Subdomains", ".example.com", 0)
	pub, _ := testKey(t)
	for _, tc := range []struct {
		name string
		bad  bool
	}{{"example.com", true}, {"www.example.com", false}, {"*.example.com", false}} {
		c := testTemplate(t, "Leaf")
		c.NotBefore, c.DNSNames = time.Now(), []string{tc.name}
		if _, err := i.issue(c, pub); (err != nil) != tc.bad {
			t.Fatalf("subdomain-only issuance of %s: %v", tc.name, err)
		}
	}
	limited := *i.chain[0]
	limited.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	i.chain[0] = testCertificate(t, &limited, root.chain[0], i.chain[0].PublicKey.(ed25519.PublicKey), root.key.(ed25519.PrivateKey))
	c := testTemplate(t, "Leaf")
	c.NotBefore, c.DNSNames = time.Now(), []string{"www.example.com"}
	c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}
	if _, err := i.issue(c, pub); err == nil {
		t.Fatal("issuer EKU restriction bypassed by one allowed usage")
	}
}

// Each subprocess has fresh Cobra flags and permits assertions on CLI exit codes.
func TestCLIProcess(t *testing.T) {
	if os.Getenv("SSL_TOOLS_TEST_CLI") != "1" {
		return
	}
	for n, arg := range os.Args {
		if arg == "--" {
			rootCmd.SetArgs(os.Args[n+1:])
			Execute()
			return
		}
	}
	t.Fatal("missing CLI arguments")
}

func runCLI(t *testing.T, bad bool, args ...string) string {
	t.Helper()
	return runCLIWithInput(t, bad, "", args...)
}

func runCLIWithInput(t *testing.T, bad bool, input string, args ...string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], append([]string{"-test.run=^TestCLIProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "SSL_TOOLS_TEST_CLI=1")
	cmd.Stdin = strings.NewReader(input)
	out, err := cmd.CombinedOutput()
	if (err != nil) != bad {
		t.Fatalf("ca %v: error=%v, want rejection=%v\n%s", args, err, bad, out)
	}
	return string(out)
}

func testIssuerArgs(t *testing.T, i *issuer) []string {
	t.Helper()
	d := t.TempDir()
	certPath, keyPath := filepath.Join(d, "issuer.pem"), filepath.Join(d, "issuer.key")
	if err := certificateToPEMFile(i.chain[0].Raw, certPath); err != nil {
		t.Fatal(err)
	}
	if err := privateKeyToPEMFile(i.key, keyPath); err != nil {
		t.Fatal(err)
	}
	args := []string{"--ca-cert", certPath, "--ca-key", keyPath, "--key-type", "ed25519"}
	if len(i.chain) > 1 {
		var ancestors [][]byte
		for _, cert := range i.chain[1:] {
			ancestors = append(ancestors, cert.Raw)
		}
		chainPath := filepath.Join(d, "ancestors.pem")
		if err := certificatesToPEMFile(ancestors, chainPath); err != nil {
			t.Fatal(err)
		}
		args = append(args, "--chain", chainPath)
	}
	return args
}

func readTestCert(t *testing.T, path string) *x509.Certificate {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := parseCertificates(b)
	if err != nil {
		t.Fatal(err)
	}
	return cs[0]
}

func writeTestCSR(t *testing.T, path string, names []string, tamper bool) {
	t.Helper()
	_, key := testKey(t)
	b, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "Requested"}, DNSNames: names}, key)
	if err != nil {
		t.Fatal(err)
	}
	if tamper {
		b[len(b)-1] ^= 1
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: b}), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestIntermediateCLI(t *testing.T) {
	d := t.TempDir()
	path := func(name string) string { return filepath.Join(d, name) }
	runCLI(t, false, "init", "--subject", "CN=Root", "--ca-key", path("root.key"), "--ca-cert", path("root.pem"), "--key-type", "ed25519", "--days", "3650")
	rootArgs := []string{"--ca-key", path("root.key"), "--ca-cert", path("root.pem"), "--key-type", "ed25519"}
	create := append([]string{"sign", "intermediate"}, rootArgs...)
	create = append(create, "--subject", "CN=Intermediate", "--key", path("intermediate.key"), "--cert", path("intermediate.pem"), "--permit-dns", "example.com", "--exclude-dns", "restricted.example.com", "--days", "730")
	runCLI(t, false, create...)
	intermediate, root := readTestCert(t, path("intermediate.pem")), readTestCert(t, path("root.pem"))
	if err := intermediate.CheckSignatureFrom(root); err != nil {
		t.Fatal(err)
	}
	if intermediate.MaxPathLen != 0 || !intermediate.MaxPathLenZero || !intermediate.PermittedDNSDomainsCritical {
		t.Fatal("incorrect intermediate constraints")
	}
	info, err := os.Stat(path("intermediate.key"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("key permissions: %v %v", info, err)
	}
	text := runCLI(t, false, "read", path("intermediate.pem"))
	if !strings.Contains(text, "Permitted DNS Domains: [example.com]") || !strings.Contains(text, "Max Path Length: 0") {
		t.Fatalf("missing constraints in read output: %s", text)
	}
	issuerArgs := []string{"--ca-key", path("intermediate.key"), "--ca-cert", path("intermediate.pem"), "--chain", path("root.pem"), "--key-type", "ed25519"}
	for n, san := range []string{"api.example.com", "example.com", "evil.test", "api.example.com,evil.test", "restricted.example.com", "*.example.com", "127.0.0.1"} {
		bad := n >= 2
		args := append([]string{"sign", "certificate"}, issuerArgs...)
		args = append(args, "--subject", "CN=Server", "--san", san, "--key", path("server.key"), "--cert", path("server.pem"), "--days", "1000")
		runCLI(t, bad, args...)
		if !bad {
			leaf := readTestCert(t, path("server.pem"))
			if leaf.NotAfter.After(intermediate.NotAfter) || leaf.SerialNumber.Cmp(intermediate.SerialNumber) == 0 {
				t.Fatal("invalid validity or reused serial")
			}
		}
	}
	for _, tc := range []struct {
		names  []string
		tamper bool
		bad    bool
	}{
		{[]string{"api.example.com"}, false, false},
		{[]string{"api.example.com", "evil.test"}, false, true},
		{[]string{"api.example.com"}, true, true},
		{nil, false, true},
	} {
		writeTestCSR(t, path("request.pem"), tc.names, tc.tamper)
		args := append([]string{"sign", "certificate"}, issuerArgs...)
		args = append(args, "--csr", path("request.pem"), "--cert", path("csr-cert.pem"), "--approve")
		runCLI(t, tc.bad, args...)
	}
	writeTestCSR(t, path("ca-request.pem"), nil, false)
	args := append([]string{"sign", "intermediate"}, rootArgs...)
	args = append(args, "--csr", path("ca-request.pem"), "--cert", path("csr-ca.pem"), "--permit-dns", "example.org", "--approve")
	runCLI(t, false, args...)
	if !readTestCert(t, path("csr-ca.pem")).IsCA {
		t.Fatal("CSR was not issued as a CA")
	}
	// A signer without its root, a delegated CA under pathLen=0, and missing
	// mandatory constraint/issuer flags must all fail at the CLI boundary.
	runCLI(t, true, "sign", "certificate", "--ca-key", path("intermediate.key"), "--ca-cert", path("intermediate.pem"), "--subject", "CN=Server", "--san", "api.example.com", "--key", path("missing-root.key"), "--cert", path("missing-root.pem"), "--key-type", "ed25519")
	args = append([]string{"sign", "intermediate"}, issuerArgs...)
	args = append(args, "--subject", "CN=Forbidden", "--key", path("forbidden.key"), "--cert", path("forbidden.pem"), "--permit-dns", "example.com")
	runCLI(t, true, args...)
	if _, err := os.Stat(path("forbidden.key")); !os.IsNotExist(err) {
		t.Fatal("rejected delegation wrote a key")
	}
	runCLI(t, true, "sign", "intermediate", "--subject", "CN=Missing", "--key", path("missing.key"), "--cert", path("missing.pem"))
}

func TestIntermediateCLIOptionsAndChainBundle(t *testing.T) {
	d := t.TempDir()
	path := func(name string) string { return filepath.Join(d, name) }
	root := testRoot(t)
	if err := privateKeyToPEMFile(root.key, path("root.key")); err != nil {
		t.Fatal(err)
	}
	if err := certificateToPEMFile(root.chain[0].Raw, path("root.pem")); err != nil {
		t.Fatal(err)
	}
	base := []string{"sign", "intermediate", "--ca-key", path("root.key"), "--ca-cert", path("root.pem"), "--key-type", "ecdsa", "--subject", "CN=Parent", "--key", path("parent.key"), "--cert", path("parent.pem")}
	for _, flags := range [][]string{
		nil,
		{"--permit-dns", "*.example.com"},
		{"--permit-dns", "example.com."},
		{"--permit-dns", "127.0.0.1"},
		{"--permit-dns", "example.com", "--max-path-len", "-1"},
		{"--permit-dns", "example.com", "--days", "0"},
		{"--permit-dns", "example.com", "--days", "-1"},
		{"--permit-dns", "example.com", "--csr", path("missing.csr")},
	} {
		args := append(append([]string{}, base...), flags...)
		runCLI(t, true, args...)
		for _, name := range []string{"parent.key", "parent.pem"} {
			if _, err := os.Stat(path(name)); !os.IsNotExist(err) {
				t.Fatalf("failed intermediate command wrote %s", name)
			}
		}
	}
	args := append(append([]string{}, base...), "--permit-dns", "example.com", "--permit-dns", "example.org", "--max-path-len", "1")
	runCLI(t, false, args...)
	parent := readTestCert(t, path("parent.pem"))
	if len(parent.PermittedDNSDomains) != 2 || parent.MaxPathLen != 1 {
		t.Fatal("repeated domain flags or positive delegation limit lost")
	}
	// Retrying must not overwrite either existing output, or leave another file.
	runCLI(t, true, args...)
	args = append(append([]string{}, args...), "--cert", path("new.pem"))
	runCLI(t, true, args...)
	if _, err := os.Stat(path("new.pem")); !os.IsNotExist(err) {
		t.Fatal("output failure did not roll back new certificate")
	}
	runCLI(t, false, "sign", "intermediate", "--ca-key", path("parent.key"), "--ca-cert", path("parent.pem"), "--chain", path("root.pem"), "--subject", "CN=Child", "--key", path("child.key"), "--cert", path("child.pem"), "--key-type", "ed25519", "--permit-dns", "team.example.com")
	child := readTestCert(t, path("child.pem"))
	if err := certificatesToPEMFile([][]byte{child.Raw, parent.Raw, root.chain[0].Raw}, path("bundle.pem")); err != nil {
		t.Fatal(err)
	}
	runCLI(t, false, "sign", "certificate", "--ca-key", path("child.key"), "--ca-cert", path("bundle.pem"), "--subject", "CN=Server", "--san", "www.team.example.com", "--key", path("server.key"), "--cert", path("server.pem"), "--key-type", "ed25519")
	leaf := readTestCert(t, path("server.pem"))
	opts := (&issuer{chain: []*x509.Certificate{child, parent, root.chain[0]}}).verifyOptions(x509.ExtKeyUsageServerAuth)
	opts.DNSName = "www.team.example.com"
	if chains, err := leaf.Verify(opts); err != nil || len(chains[0]) != 4 {
		t.Fatalf("multi-level chain verification: %v", err)
	}
	// A leaf output must never overwrite the signing key, including hard links.
	if err := os.Link(path("child.key"), path("key-alias")); err != nil {
		t.Fatal(err)
	}
	runCLI(t, true, "sign", "certificate", "--ca-key", path("child.key"), "--ca-cert", path("bundle.pem"), "--subject", "CN=Server", "--san", "www.team.example.com", "--key", path("key-alias"), "--cert", path("server.pem"), "--key-type", "ed25519")
}
