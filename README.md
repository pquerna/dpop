# dpop

[![GoDoc](https://godoc.org/github.com/pquerna/dpop?status.svg)](https://godoc.org/github.com/pquerna/dpop) [![Build Status](https://travis-ci.org/pquerna/dpop.svg?branch=master)](https://travis-ci.org/pquerna/dpop)

Go library for DPoP (OAuth 2.0 Demonstration of Proof-of-Possession at the Application Layer).

This implementation is current for [draft-fett-oauth-dpop-02](https://tools.ietf.org/html/draft-fett-oauth-dpop-02), published July 8, 2019.

# Usage

## Go API

See the [godoc](https://godoc.org/github.com/pquerna/dpop).

## CLI

This repository also contains a small command line tool that can be used for trying out DPoP, `demo-dpop`:

```
# build the demo-dpop binary
make

# generates a new private key to use for signing
demo-dpop create-key --key-name my-local-key

# Outputs an example curl line with a DPoP proof in a header, which can be used during a token exchange:
demo-dpop proof --key-name my-local-key --url https://as.example.com/token --method POST

# Outputs an example curl line with a DPoP proof header, which can be used in conjunction with an access
# token for a resource server access:
demo-dpop proof --key-name my-local-key --url https://resource1.example.com/api/endpoint --method POST
```

# Dependencies

- Go 1.12 (using go modules)

## Code signing

This repo also contains a work-in-progress to use the Secure Enclave Processor (SEP) as a key-storage for a signing
a DPoP JWT. This has additional dependencies:

- macOS >= 10.12
- TouchID hardware
- Developer Tools installed
- Code Signing certificate available

(macOS requires code signing to use the Keychain with the enclave)

# License

`dpop` is licensed under the [Apache License, Version 2.0](./LICENSE)
