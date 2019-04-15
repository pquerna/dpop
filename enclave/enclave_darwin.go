// +build darwin

package enclave

import (
	"sync"
)

var availableOnce sync.Once
var isAvailable bool
var isCodeSigned bool

func available() bool {
	availableOnce.Do(func() {
		isAvailable = checkLAContext()
		isCodeSigned, _ = IsCodeSigned()
	})
	return isAvailable && isCodeSigned
}
