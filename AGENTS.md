# Repository guidance

## Purpose and scope

This repository builds `ca`, a small Go command-line utility that simplifies
common OpenSSL workflows: creating a self-signed CA, generating private keys and
certificate signing requests (CSRs), signing certificates with a CA, inspecting
PEM files, and converting between PEM and PKCS#12. The README also calls the
project `ssl-utils`; the module is `github.com/deitch/ssl-tools`.

Keep changes focused on this CLI. It uses local files, Go's standard crypto
libraries, Cobra for commands, and `software.sslmate.com/src/go-pkcs12` for
PKCS#12 conversion. There is no service, database, or external OpenSSL runtime
dependency.

## Code map

- `main.go`: delegates to `cmd.Execute()`.
- `cmd/root.go`: root command registration and global `--verbose` flag.
- `cmd/common.go`: key generation, PKCS#8 PEM output, certificate and CSR
  writing, subject parsing, CA loading, signing, and key-type validation.
- `cmd/init.go`: `ca init`, creating a key and self-signed CA certificate.
- `cmd/csr.go`: `ca csr`, creating a private key and CSR with DNS/IP SANs.
- `cmd/sign.go`: signing parent command and shared signing flags.
- `cmd/sign_subject.go`: `ca sign subject`, generating a key and issuing a
  certificate directly from a subject and optional SANs.
- `cmd/sign_csr.go`: issuing a certificate using an existing CSR's public key,
  subject, and DNS/IP SANs, with an interactive approval or `--approve`.
- `cmd/read.go`: PEM inspection, private-key parsing, and usage formatting.
- `cmd/convert.go`: `ca convert pkcs12 read|write <file>`, splitting a bundle
  into PEM files or building a bundle/trust store from PEM inputs.
- `.github/workflows/`: pull-request/master checks and tag-triggered release
  builds. Release targets are Linux amd64/arm64, macOS amd64, and Windows amd64.

## Build and validation

Use the Go version declared in `go.mod` (currently `1.25.0`) or a compatible
newer version. Dependencies are pinned in `go.mod` and `go.sum`.

```sh
make fmt-check
make vet
make test
make build
```

`make fmt` formats Go sources. `make build` writes
`dist/ca-<os>-<arch>` and links `./ca` for native builds. Cross-compile with
`make build OS=linux ARCH=arm64`; `make built-name` prints the target path.
`make install` writes to `GOBINDIR`, defaulting to `$(go env GOPATH)/bin`.

The Makefile's binary targets do not track Go source prerequisites. After code
changes, use `go build -o /tmp/ssl-tools-ca .` to ensure a fresh build, or remove
the relevant generated binary before running `make build` again. `make clean`
only removes the root `ca` link; it does not clear `dist/`.

CI also runs golangci-lint v2.10. The local `make lint` installer defaults to
v1.46.2, so the local and CI linter versions differ. Avoid inadvertently
installing the old version when reproducing a CI issue.

There are currently no `_test.go` files. A passing `go test ./...` checks package
compilation but provides no behavioral coverage. Add focused regression tests
for behavior changes, using temporary directories and freshly generated test
keys. For command paths that call `log.Fatal` or `os.Exit`, use subprocess tests
or test extracted helpers. Global Cobra commands and flag variables retain state
within a process; do not assume command invocations are isolated or parallel-safe.

For certificate changes, verify the generated artifacts by parsing them and
checking signatures, SANs, usages, CA constraints, validity, and key matching as
appropriate. For conversion changes, exercise a round trip and compare parsed
keys/certificates and the chain. Use disposable output paths for CLI smoke tests.
If dependencies cannot be downloaded or a check cannot run, report that limitation
explicitly rather than treating it as a pass.

## Editing conventions

- Follow the existing Go formatting and command/helper organization; keep
  reusable crypto and file handling in helpers rather than duplicating it in
  command handlers.
- Preserve existing command names, flags, file formats, and prompts unless the
  task explicitly changes them. Update README examples and help text together
  when changing the CLI.
- Use `crypto/rand` and standard crypto APIs. Generated private keys are
  unencrypted PKCS#8 PEM; key generation supports RSA, Ed25519, and ECDSA P-256.
  Reading also accepts PKCS#1 RSA and SEC1 EC private keys.
- Keep generated keys, certificates, bundles, and binaries out of commits.
  `ca`, `dist/`, `out/`, and `tmp/` are ignored local artifacts. Do not inspect or
  overwrite existing local key material when generating test fixtures.
- Treat changes to key permissions, overwriting files, CSR validation,
  certificate serials, validity, and extensions as deliberate behavior changes
  with focused validation. Do not silently change cryptographic policy as part
  of unrelated refactoring.

## Existing discrepancies and pitfalls

These describe the current implementation, not behavior to reproduce in new code.
Verify them when working on the affected command and keep unrelated fixes scoped
separately.

- The README shows `ca sign csr`, but `signCsrCmd.Use` is `"sign"`, making the
  registered path `ca sign sign`. The README's `ca read --file ...` is also stale:
  the implementation takes a positional file. CSR signing has no `--key` or
  `--san` flags; it reuses the CSR's public key and SANs.
- `--days` is registered only on `init`; signing uses the shared `certDays`
  variable with its initialized default. Standalone `csr` exposes neither
  `--key-type` nor `--key-size` and uses the initialized RSA defaults.
- All issued certificates currently use serial number 1. CSR signing parses
  requests without calling `CheckSignature()`. Subject-issued certificates allow
  server and client auth, while CSR-issued certificates allow server auth only.
- Subject parsing accepts comma-separated or leading-slash DNs and supports
  `C`, `O`, `OU`, `ST`, `L`, and `CN`. Malformed recognized components lacking
  `=` can panic; separator escaping is handled only partially.
- PEM output uses `os.Create`, so it can overwrite existing files and private-key
  permissions depend on the process umask. PKCS#12 output requests mode `0600`
  when creating a new file.
- PEM inspection reads only the first block. PKCS#12 writing likewise reads only
  the first certificate from the supplied CA PEM file, despite accepting a
  chain file in its help text.
- Command handlers commonly terminate via `log.Fatal`; `Execute()` discards
  Cobra's returned error, so CLI failures do not consistently yield nonzero exit
  status. The `--verbose` flag is registered but currently unused.
