package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSigningInputModes(t *testing.T) {
	d := t.TempDir()
	path := func(name string) string { return filepath.Join(d, name) }
	root := testRoot(t)
	if err := privateKeyToPEMFile(root.key, path("root.key")); err != nil {
		t.Fatal(err)
	}
	if err := certificateToPEMFile(root.chain[0].Raw, path("root.pem")); err != nil {
		t.Fatal(err)
	}
	writeTestCSR(t, path("request.pem"), []string{"api.example.com"}, false)
	for _, command := range []string{"certificate", "intermediate"} {
		t.Run(command, func(t *testing.T) {
			base := []string{"sign", command, "--ca-key", path("root.key"), "--ca-cert", path("root.pem"), "--cert", path("issued.pem"), "--key-type", "ed25519", "--approve"}
			if command == "intermediate" {
				base = append(base, "--permit-dns", "example.com")
			}
			for _, tc := range []struct {
				name, message string
				flags         []string
			}{
				{"neither", "specify --subject and --key, or --csr", nil},
				{"subject without key", "specify --subject and --key, or --csr", []string{"--subject", "CN=Server"}},
				{"key without subject", "specify --subject and --key, or --csr", []string{"--key", path("issued.key")}},
				{"both sources", "cannot be combined", []string{"--csr", path("request.pem"), "--subject", "CN=Server", "--key", path("issued.key")}},
				{"CSR with subject", "cannot be combined", []string{"--csr", path("request.pem"), "--subject", "CN=Server"}},
				{"CSR with key", "cannot be combined", []string{"--csr", path("request.pem"), "--key", path("issued.key")}},
				{"CSR with empty subject", "cannot be combined", []string{"--csr", path("request.pem"), "--subject", ""}},
				{"CSR with empty key", "cannot be combined", []string{"--csr", path("request.pem"), "--key", ""}},
				{"empty CSR", "--csr requires a file path", []string{"--csr", ""}},
				{"empty subject", "specify --subject and --key, or --csr", []string{"--subject", "", "--key", path("issued.key")}},
				{"empty key", "specify --subject and --key, or --csr", []string{"--subject", "CN=Server", "--key", ""}},
			} {
				t.Run(tc.name, func(t *testing.T) {
					args := append(append([]string{}, base...), tc.flags...)
					out := runCLI(t, true, args...)
					if !strings.Contains(out, tc.message) {
						t.Fatalf("expected %q in error: %s", tc.message, out)
					}
					for _, name := range []string{"issued.key", "issued.pem"} {
						if _, err := os.Stat(path(name)); !os.IsNotExist(err) {
							t.Fatalf("invalid input mode created %s", name)
						}
					}
				})
			}
			if command == "certificate" {
				for _, san := range []string{"outside.test", ""} {
					args := append(append([]string{}, base...), "--csr", path("request.pem"), "--san", san)
					if out := runCLI(t, true, args...); !strings.Contains(out, "cannot be combined") {
						t.Fatalf("CSR SAN override was not rejected: %s", out)
					}
				}
			}
		})
	}
}

func TestSigningHelp(t *testing.T) {
	out := runCLI(t, false, "sign", "--help")
	if !strings.Contains(out, "certificate") || !strings.Contains(out, "intermediate") || strings.Contains(out, "Generate a private key, generate a CSR") {
		t.Fatalf("expected unified commands in help: %s", out)
	}
	out = runCLI(t, false, "sign", "certificate", "--help")
	for _, flag := range []string{"--subject", "--key", "--csr", "--san", "--cert"} {
		if !strings.Contains(out, flag) {
			t.Fatalf("help missing %s: %s", flag, out)
		}
	}
}

func TestRemovedSigningCommands(t *testing.T) {
	for _, command := range []string{"csr", "subject", "sign"} {
		t.Run(command, func(t *testing.T) {
			out := runCLI(t, true, "sign", command, "--ca-key", "unused.key", "--ca-cert", "unused.pem")
			if !strings.Contains(out, "unknown command") {
				t.Fatalf("removed command should be rejected before issuance: %s", out)
			}
		})
	}
}
