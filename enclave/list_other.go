// +build !darwin

package enclave

func list_keypairs(app string) ([]Keypair, error) {
	return nil, ErrNoBackend
}
