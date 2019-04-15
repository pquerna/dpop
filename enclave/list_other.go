// +build !darwin

package enclave

func list_keypairs() ([]Keypair, error) {
	return nil, ErrNoBackend
}
