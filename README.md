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
ca sign subject --subject "CN=server.victory.yours,C=US,ST=NV" --ca-key ./ca/key.pem --ca-cert ./ca/cert.pem --key ./server/key.pem --cert ./server/cert.pem
```

It supports Subject Alternative Names (SANs), by passing them comma-separated, for example:

```
ca sign subject --subject "CN=server.victory.yours,C=US,ST=NV" --ca-key ./ca/key.pem --ca-cert ./ca/cert.pem --key ./server/key.pem --cert ./server/cert.pem --san 1.2.3.4,foo.bar.com
```

### Sign a CSR from a CA

```
ca sign csr --ca-key ./ca/key.pem --ca-cert ./ca/cert.pem --key ./server/key.pem --cert ./server/cert.pem --csr ./server/csr.pem
```

It supports Subject Alternative Names (SANs), by passing them comma-separated, for example:

```
ca sign csr --ca-key ./ca/key.pem --ca-cert ./ca/cert.pem --key ./server/key.pem --cert ./server/cert.pem --csr ./server/csr.pem --san 1.2.3.4,foo.bar.com
```

### Read a File

Read the basic contents of a key, certificate or certificate request file, pem-encoded. It won't give you the _entire_ output that you would get
from openssl, but gives the basics you need most of the time when working with certificates:

```
ca read --file /path/to/file
```

It will try to determine if the file is a certificate, a private key or a certificate request, based on its PEM-encoding.

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
