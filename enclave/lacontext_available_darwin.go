// +build darwin

package enclave

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -lobjc -framework CoreFoundation -framework LocalAuthentication
#import <LocalAuthentication/LocalAuthentication.h>

short dpop_enclave_lacontext_available_bio() {
	short rv = -1;
	LAContext *lctx = [[LAContext alloc] init];
	if ([lctx canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error: nil]) {
		rv = 0;
	}
	CFRelease(lctx);
	return rv;
}
*/
import "C"

func checkLAContext() bool {
	return C.dpop_enclave_lacontext_available_bio() == 0
}
