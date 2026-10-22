# ssl-utils

**openssl is painful!**

Sure, it can do lots of things, the swiss army knife of ssl, but in many cases, you just want to:

* generate a CA key and cert
* generate a few other keys and certs signed by that CA

The number of confusing steps to do this in openssl is too many.

ssl-utils is a simple utility that lets you do _just_ the above:

* generate a CA
* sign things with the CA
* read a key, certificate, or certificate request file

That is it!

## Installing

Just download the file for your operating system and architecture on the "Releases" page.

For those who just love compiling, clone this repo and run `make build`.

## How to use it

Note that all commands have a help, so you should run `ca --help` or `ca help` or even `ca <command> help` to see all of the options.

### Generate a CSR

```
ca csr --subject "CN=server.victory.yours,C=US,ST=NV" --key ./server/key.pem --csr ./server/csr.pem
```
It supports Subject Alternative Names (SANs), by passing them comma-separated, for example:

```
ca csr --subject "CN=server.victory.yours,C=US,ST=NV" --key ./server/key.pem --csr ./server/csr.pem --san 1.2.3.4,foo.bar.com
```

### Generate a CA

```
./ca
```

Run that, it will tell you your arguments. Basically, you need to give it the subject for your CA in `A=B,C=D,` format,
and where to save your CA key and file. That is it. For example:

```
ca init --subject "CN=ca.victory.mine,C=US,ST=CA" --ca-key ./ca/key.pem --ca-cert ./ca/cert.pem
```

That is it!

### Create a key and signed cert from a CA

Now you can generate a key/cert using that CA, or any other CA key/cert you have lying around (who leaves them "lying around"?).

```
ca sign certificate --subject "CN=server.victory.yours,C=US,ST=NV" --ca-key ./ca/key.pem --ca-cert ./ca/cert.pem --key ./server/key.pem --cert ./server/cert.pem
```

It supports Subject Alternative Names (SANs), by passing them comma-separated, for example:

```
ca sign certificate --subject "CN=server.victory.yours,C=US,ST=NV" --ca-key ./ca/key.pem --ca-cert ./ca/cert.pem --key ./server/key.pem --cert ./server/cert.pem --san 1.2.3.4,foo.bar.com
```

### Sign a CSR from a CA

```
ca sign certificate --ca-key ./ca/key.pem --ca-cert ./ca/cert.pem --cert ./server/cert.pem --csr ./server/csr.pem
```

The subject and SANs come from the CSR, whose signature is verified before issuance.
Signing asks for approval; use `--approve` for unattended signing.

Both `ca sign certificate` and `ca sign intermediate` require exactly one input
mode: `--csr <file>`, or `--subject <DN>` together with `--key <output>`.
Combining `--csr` with `--subject` or `--key`, or providing neither mode, fails.
For leaf certificates, `--san` is available only in subject mode; CSR mode uses
SANs from the request and rejects `--san` overrides. `--cert` is always required.

### Create and use an intermediate CA

An intermediate CA is signed by a parent CA and can issue certificates without
access to the root's private key. This example delegates only `example.com` and
its subdomains, excluding `restricted.example.com` and its subdomains.

Create the directories first. Use disposable paths when experimenting; existing
leaf-generation commands can overwrite their output files.

```sh
mkdir -p root intermediate server
ca init --subject "CN=Example Root CA" \
  --ca-key root/key.pem --ca-cert root/cert.pem --days 3650

ca sign intermediate --subject "CN=Example Issuing CA" \
  --ca-key root/key.pem --ca-cert root/cert.pem \
  --key intermediate/key.pem --cert intermediate/cert.pem \
  --permit-name example.com --exclude-name restricted.example.com \
  --max-path-len 0 --days 730

ca sign certificate --subject "CN=api.example.com" --san api.example.com \
  --ca-key intermediate/key.pem --ca-cert intermediate/cert.pem \
  --chain root/cert.pem --key server/key.pem --cert server/cert.pem --days 90

cat server/cert.pem intermediate/cert.pem > server/fullchain.pem
```

Clients trust **the root certificate**. Configure the server with its private key
and `fullchain.pem` (leaf first, followed by the intermediate). Keep the root
private key offline after issuing the intermediate; subsequent leaf issuance uses
only the intermediate key and the public ancestor certificates. Do not install
the intermediate as a separate trust anchor: clients must validate the chain to
the intended root for the hierarchy's constraints to apply.

`ca sign certificate` also accepts `--chain` and uses the same issuer-policy checks.
`--days` defaults to 365 for signing; certificate expiry is capped at the earliest
expiry in the issuer chain. Each new certificate receives a random serial number.
`ca read intermediate/cert.pem` displays CA status, path length, and DNS/IP constraints.

Intermediate creation requires at least one permitted DNS domain in
`--permit-name`. Both `--permit-name` and `--exclude-name` accept mixed DNS names,
bare IP addresses, and CIDRs, using repeated flags or comma-separated lists. The
CLI automatically separates DNS and IP constraints when encoding the certificate.
Constraints
are encoded in a **critical X.509 Name Constraints extension**:

- `example.com` permits the apex and all its subdomains; `.example.com` permits
  subdomains only (supported by Go's verifier). Use ASCII/punycode domains without
  trailing dots. DNS constraint values cannot contain wildcards.
- Exclusions override permissions. Every DNS SAN is checked; combining an allowed
  name with an outside-domain or excluded name fails. Wildcard leaf SANs are
  supported, but any overlap with an excluded subtree is conservatively rejected.
- Leaf certificates require DNS and/or explicitly permitted IP SANs. IP issuance
  requires an IP address or CIDR in `--permit-name`; DNS-only intermediates still refuse
  IP SANs. Email and URI identities remain unsupported for constrained issuance.
  DNS/IP constraints do not constrain arbitrary subject common names, email, or
  URI identities issued by other software. Use SAN-aware TLS clients.
- `--max-path-len 0` is the default and prevents further intermediate delegation.
  Set a positive limit explicitly to allow more CA levels. Each child must fit
  all ancestors' remaining depth and narrow or retain their permitted DNS scope;
  ancestor DNS exclusions are inherited. Intermediate subjects must differ from
  all ancestor subjects; self-issued rollover chains are not supported.

For example, `--permit-name esi.bak,127.0.0.1,::1` allows DNS names such as
`vault.hq.esi.bak` plus both loopback addresses. A bare IPv4 address becomes a
`/32` constraint; a bare IPv6 address becomes a `/128` constraint. Then issue the server certificate with
`--san vault.hq.esi.bak,127.0.0.1` (and `::1` if needed).

Use CIDRs for broader IP ranges, for example `--permit-name esi.bak,10.0.0.0/8`
and `--exclude-name restricted.esi.bak,10.1.0.0/16`. Exclusions take precedence;
child CAs cannot widen ancestor ranges and inherit ancestor exclusions.
Host bits in a CIDR are normalized to its network; IPv4-mapped IPv6 CIDRs are
rejected. DNS and IP permissions apply independently, and every SAN must pass.

An existing DNS-only intermediate must be reissued by its parent to enable IPs;
a child cannot add IP permissions that its DNS-constrained ancestor lacks. Use
an existing intermediate CSR with `ca sign intermediate --csr ... --permit-name
esi.bak,127.0.0.1 ...` to retain its private key, or generate a new
key/certificate pair. Write to new output paths: intermediate issuance refuses
to overwrite existing files. Keep the same required DNS scope, exclusions,
validity, and path-length policy when reissuing. The permitted IP ranges are
encoded in the intermediate certificate, so chain-verifying clients also reject
IP SANs outside those ranges.

A signing intermediate needs its **complete public chain to a self-signed root**.
Use `--chain` for ancestors in order: immediate parent first, root last. For a
second-level intermediate, for example:

```sh
cat parent-intermediate.pem root.pem > ancestors.pem
```

Alternatively, bundle the signing intermediate and all its ancestors, in that
order, in `--ca-cert` and omit `--chain`. Do not duplicate bundled ancestors in
`--chain`. Invalid signatures, missing/reordered ancestors, non-CA signers,
expired/not-yet-valid issuers, and chain constraints cause signing to fail. The
explicitly supplied final root is the trust anchor for these local checks; the
CLI does not consult the system trust store or perform revocation checks.

To keep the intermediate private key off the root-signing machine, generate a CSR
on the intermediate machine, then transfer only the CSR to the root machine:

```sh
ca csr --subject "CN=Example Issuing CA" \
  --key intermediate/key.pem --csr intermediate/request.pem

# On the root-signing machine:
ca sign intermediate --csr intermediate/request.pem \
  --ca-key root/key.pem --ca-cert root/cert.pem \
  --cert intermediate/cert.pem --permit-name example.com --days 730 --approve
```

Return the signed certificate to the intermediate machine. `--csr` cannot be
combined with `--subject` or `--key`; CA privileges and constraints are set by the
signing flags, not by requested CSR extensions. Omit `--approve` to review the
subject interactively. Intermediate output paths must not already exist, and
new private keys are created with mode `0600`.

### Read a File

Read the basic contents of a key, certificate or certificate request file, pem-encoded. It won't give you the _entire_ output that you would get
from openssl, but gives the basics you need most of the time when working with certificates:

```
ca read /path/to/file
```

It will try to determine if the file is a certificate, a private key or a certificate request, based on its PEM-encoding.

### Convert PKCS#12 files

Export a key bundle using `--key` and `--cert` together, optionally with a CA
certificate supplied through `--ca`. Exports use the library's Modern encryption
profile. Supplying `--key` without `--cert` returns an error.

```sh
ca convert pkcs12 write server.p12 --key server.key --cert server.pem --ca root.pem --password example-password
ca convert pkcs12 read server.p12 --key extracted.key --cert extracted.pem --ca extracted-ca.pem --password example-password
```

For certificate-only trust stores, use `--ca` for both export and import. Import
writes all trusted certificates into that PEM file; it leaves `--key` and `--cert`
outputs untouched because a trust store contains neither a private key nor a
leaf certificate.

```sh
ca convert pkcs12 write trust.p12 --ca root.pem --password example-password
ca convert pkcs12 read trust.p12 --ca trusted.pem --password example-password
```

## Building

ssl-tools is built with golang. If you have golang installed, just do:

```
make build
```

and `ca` will be available in this directory. To install into golang's standard bin path:

```
make install
```

By default, it builds for your local OS and ARCH. To cross-compile:

```
make build OS=<target> ARCH=<target>
```

Run the tests, including race detection, with `make test`.
