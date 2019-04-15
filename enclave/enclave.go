package enclave

import (
	"crypto"
	"errors"

	"gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/cryptosigner"
)

func Available() bool {
	return available()
}

type Keypair interface {
	crypto.Signer

	Label() string
	ID() string
}

func List(app string) ([]Keypair, error) {
	return list_keypairs(app)
}

func Generate(app string, label string) (Keypair, error) {
	return generate_keypair(app, label, true, true)
}

func OpaqueSigner(kp Keypair) jose.OpaqueSigner {
	return cryptosigner.Opaque(kp)
}

var (
	ErrNoBackend = errors.New("enclave: no backend available")
)
