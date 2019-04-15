package enclave

import (
	"testing"
)

func TestAvailable(t *testing.T) {
	a := Available()
	t.Logf("Available = %v", a)
}
