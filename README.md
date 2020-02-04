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

## How to use it


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
ca sign --subject "CN=server.victory.yours,C=US,ST=NV" --ca-key ./ca/key.pem --ca-cert ./ca/cert.pem --key ./server/key.pem --cert ./server/cert.pem
```

It supports Subject Alternative Names (SANs), by passing them comma-separated, for example:

```
ca sign --subject "CN=server.victory.yours,C=US,ST=NV" --ca-key ./ca/key.pem --ca-cert ./ca/cert.pem --key ./server/key.pem --cert ./server/cert.pem --san 1.2.3.4,foo.bar.com
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
