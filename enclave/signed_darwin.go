// +build darwin

package enclave

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -lobjc -framework Foundation -framework CoreFoundation -framework Security
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

void dpop_enclave_codesign_check_self(uint32_t *rv, CFErrorRef *errout) {
	OSStatus st;
	SecCodeRef memself;
	SecStaticCodeRef self;
	CFErrorRef err = nil;
	*rv = -1;
	*errout = nil;

	st = SecCodeCopySelf(kSecCSDefaultFlags, &memself);
	if (st != 0) {
		*rv = -2;
		*errout = CFErrorCreate(kCFAllocatorDefault,
			kCFErrorDomainOSStatus,
			st,
			NULL);
		return;
	}

	st = SecCodeCopyStaticCode(memself, kSecCSDefaultFlags, &self);
	if (st != 0) {
		*rv = -3;
		*errout = CFErrorCreate(kCFAllocatorDefault,
			kCFErrorDomainOSStatus,
			st,
			NULL);
		return;
	}

	st = SecStaticCodeCheckValidityWithErrors(self,
		kSecCSDefaultFlags,
		NULL,
		&err);

	if (err != nil) {
		*errout = err;
	}

	if (st == 0) {
		*rv = 1;
	}
}

*/
import "C"

import (
	"fmt"
)

func IsCodeSigned() (bool, error) {
	// background reading:
	// 	https://golang.org/pkg/debug/macho/#File.Segment
	// 	http://www.newosxbook.com/articles/CodeSigning.pdf
	// originally was going to use SecStaticCodeCheckValidityWithErrors
	// 	https://developer.apple.com/documentation/security/1395252-secstaticcodecheckvaliditywither?language=objc
	// but its just easier to check the running image with SecCodeCopySelf and SecStaticCodeCheckValidityWithErrors

	var signed C.uint32_t
	var cerr C.CFErrorRef

	C.dpop_enclave_codesign_check_self(&signed, &cerr)
	if cerr != 0 {
		// this is the most common case for unsigned code.
		err := fmt.Errorf("IsCodeSigned: failed: %d: %s", uint32(signed), cfErrToStr(cerr))
		return false, err
	}

	if signed == 1 {
		return true, nil
	}

	return false, nil
}
