// +build !darwin

package enclave

func generate_keypair(app string, label string, onEnclave bool, permanent bool) (Keypair, error) {
	return nil, ErrNoBackend
}
