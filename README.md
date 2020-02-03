# ssl-utils

**openssl is painful!**

Sure, it can do lots of things, is the swiss army knife of ssl, but in many cases, you just want to:

* generate a CA key and cert
* generate a few other keys and certs signed by that CA

The number of confusing steps to do this in openssl is too many.

ssl-utils is a simple utility that lets you do _just_ the above: generate a CA, sign things with the CA. That is it!

## How to use it

```
./ca.sh
```

Run that, it will tell you your arguments. Basically, you need to give it the subject for your CA in `/A=B/C=D/` format,
and where to save your CA key and file. That is it. For example:

```
./ca.sh "/CN=ca.victory.mine/C=US/ST=CA" ./ca/key.pem ./ca/cert.pem
```

That is it!

Now you can generate a key/cert using that CA, or any other CA key/cert you have lying around (who leaves them "lying around"?).

```
./sign-cert.sh
```

and it will tell you the arguments. You give it the subject, where to find the CA cert and key, where to save the generated
cert and key, and if there are subjectAlternativeNames (SANs), pass those, comma-separated. For example:

```
./sign-cert.sh "/CN=server.victory.mine/C=US/ST=CA" ./server/key.pem ./server/cert.pem ./ca/key.pem ./ca/cert.pem 127.0.0.1,server.victory.mine,10.10.50.60
```

## Prerequisities

These tools depend on your having `cfssl` and `jq`. But if you don't have them, don't panic! As long as you have [docker](docker.com) installed,
it will run them from there.

