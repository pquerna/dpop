// +build darwin

package enclave

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -lobjc -framework Foundation -framework CoreFoundation -framework Security
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

typedef struct dpop_enclave_keygen_params_t {
	char *app;
	char *label;
	int enclave;
	int permanent;
} dpop_enclave_keygen_params_t;

typedef struct dpop_enclave_keygen_result_t {
	CFErrorRef err;
	SecKeyRef privateKey;
	SecKeyRef publicKey;
} dpop_enclave_keygen_result_t;

void dpop_enclave_keygen_create(dpop_enclave_keygen_params_t *p, dpop_enclave_keygen_result_t **out) {
	// TODO(pquenra): handle errors
	dpop_enclave_keygen_result_t *rv = NULL;
	SecKeyRef publicKey = NULL;
	SecKeyRef privateKey = NULL;
	CFErrorRef err = NULL;
	NSMutableDictionary *params = NULL;
	CFStringRef acl = kSecAttrAccessibleAlwaysThisDeviceOnly;

	rv = calloc(1, sizeof(dpop_enclave_keygen_result_t));
	*out = rv;

	CFStringRef label = CFStringCreateWithBytes(kCFAllocatorDefault,
		(const unsigned char *)p->label,
		strlen(p->label), kCFStringEncodingASCII, 0);
	CFDataRef appTag = CFDataCreate(kCFAllocatorDefault,
		(const unsigned char *)p->app,
		strlen(p->app));

	if (p->enclave != 0) {
		acl = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly;
	}

	// kSecAttrAccessibleAfterFirstUnlock vs kSecAttrAccessibleAlwaysThisDeviceOnly
	// TODO(pquerna): kSecAccessControlTouchIDAny; i don't think its needed?
	SecAccessControlRef sac = SecAccessControlCreateWithFlags(kCFAllocatorDefault,
		kSecAttrAccessibleAfterFirstUnlock,
		kSecAccessControlPrivateKeyUsage,
		&err);
	if (err != nil) {
		goto cleanup;
	}

	params = [[NSMutableDictionary alloc] init];

	params[(id)kSecAttrLabel] = (id)label;
	params[(id)kSecAttrTokenID] =(id)kSecAttrTokenIDSecureEnclave;
	params[(id)kSecAttrKeyType] = (id)kSecAttrKeyTypeECSECPrimeRandom;
	params[(id)kSecAttrKeySizeInBits] = @256;
	params[(id)kSecAttrSynchronizable] = @NO;
	params[(id)kSecAttrApplicationTag] = (id)appTag;

	if (p->enclave != 0) {
		params[(id)kSecAttrTokenID] = (id)kSecAttrTokenIDSecureEnclave;
	}

	if (p->permanent != 0) {
        params[(id)kSecPrivateKeyAttrs] =  @{
				(id)kSecAttrApplicationTag: (id)appTag,
            	(id)kSecAttrAccessControl: (id)sac,
            	(id)kSecAttrIsPermanent: @YES,
        	};
	} else {
        params[(id)kSecPrivateKeyAttrs] =  @{
				(id)kSecAttrApplicationTag: (id)appTag,
            	(id)kSecAttrAccessControl: (id)sac,
            	(id)kSecAttrIsPermanent: @NO,
        	};
	}


	// SecKeyCreateRandomKey vs SecKeyGeneratePair:
	// SecKeyCreateRandomKey is 10.12+, SecKeyGeneratePair is old.
	privateKey = SecKeyCreateRandomKey((CFDictionaryRef)params, &err);
	if (err != nil) {
		goto cleanup;
	}
	publicKey = SecKeyCopyPublicKey(privateKey);

	rv->publicKey = publicKey;
	publicKey = nil;
	rv->privateKey = privateKey;
	privateKey = nil;

cleanup:
	if (err != nil) {
		rv->err = err;
	}
	if (label != nil) {
		CFRelease(label);
	}
	if (params != nil) {
		CFRelease(params);
	}
	if (appTag != nil) {
		CFRelease(appTag);
	}
	if (sac != nil) {
		CFRelease(sac);
	}
	if (privateKey != nil) {
		CFRelease(privateKey);
	}
	if (publicKey != nil) {
		CFRelease(publicKey);
	}
}

void dpop_enclave_keygen_result_free(dpop_enclave_keygen_result_t *kr) {
	if (kr->err != nil) {
		CFRelease(kr->err);
	}
	if (kr->privateKey != nil) {
		CFRelease(kr->privateKey);
	}
	if (kr->publicKey != nil) {
		CFRelease(kr->publicKey);
	}
	free(kr);
}

*/
import "C"

import (
	"fmt"
	"unsafe"
)

func generate_keypair(app string, label string, onEnclave bool, permanent bool) (Keypair, error) {
	var kr *C.dpop_enclave_keygen_result_t
	var p C.dpop_enclave_keygen_params_t

	p.app = C.CString(app)
	defer C.free(unsafe.Pointer(p.app))
	p.label = C.CString(label)
	defer C.free(unsafe.Pointer(p.label))
	p.enclave = 0
	if onEnclave {
		p.enclave = 1
	}

	C.dpop_enclave_keygen_create(&p, &kr)
	defer C.dpop_enclave_keygen_result_free(kr)
	if kr.err != 0 {
		err := fmt.Errorf("dpop_enclave_keygen_create: failed: %s", cfErrToStr(kr.err))
		return nil, err
	}
	return newKeypair(kr.publicKey, kr.privateKey)
}

func cfErrToStr(cerr C.CFErrorRef) string {
	if cerr == 0 {
		return ""
	}
	desc := C.CFErrorCopyDescription(cerr)
	defer C.CFRelease((C.CFTypeRef)(desc))
	return cfstrToStr(desc)
}

func cfstrToStr(cfstr C.CFStringRef) string {
	l := C.CFStringGetLength(cfstr)
	buf := make([]byte, l*2)
	cbuf := (*C.char)(unsafe.Pointer(&buf[0]))
	C.CFStringGetCString(cfstr, cbuf, l*2, C.kCFStringEncodingUTF8)
	return C.GoString(cbuf)
}

func cfDataToBytes(data C.CFDataRef) []byte {
	return C.GoBytes(unsafe.Pointer(C.CFDataGetBytePtr(data)), C.int(C.CFDataGetLength(data)))
}

func bytesToCFData(data []byte) C.CFDataRef {
	var ptr *C.UInt8
	if len(data) > 0 {
		ptr = (*C.UInt8)(&data[0])
	}
	return C.CFDataCreate(C.kCFAllocatorDefault, ptr, C.CFIndex(len(data)))
}
