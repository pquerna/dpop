// +build darwin

package enclave

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -lobjc -framework Foundation -framework CoreFoundation -framework Security
#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <Security/Security.h>

typedef struct dpop_enclave_list_params_t {
	char *app;
} dpop_enclave_list_params_t;


typedef struct dpop_enclave_list_item_t dpop_enclave_list_item_t;
struct dpop_enclave_list_item_t {
	SecKeyRef privateKey;
	SecKeyRef publicKey;

	dpop_enclave_list_item_t *next;
};

typedef struct dpop_enclave_list_result_t {
	CFErrorRef err;
	dpop_enclave_list_item_t *items;
} dpop_enclave_list_result_t;


void dpop_enclave_list(dpop_enclave_list_params_t *p, dpop_enclave_list_result_t **out) {
	OSStatus st;
	CFArrayRef data = NULL;
	CFErrorRef err = NULL;
	NSMutableDictionary *params = NULL;
	dpop_enclave_list_result_t *rv = NULL;

	CFDataRef appTag = CFDataCreate(kCFAllocatorDefault,
		(const unsigned char *)p->app,
		strlen(p->app));

	rv = calloc(1, sizeof(dpop_enclave_list_result_t));
	*out = rv;

	params = [[NSMutableDictionary alloc] init];

	params[(id)kSecClass] = (id)kSecClassKey;
	params[(id)kSecAttrKeyClass] = (id)kSecAttrKeyClassPrivate;
	params[(id)kSecReturnRef] = (id)kCFBooleanTrue;
	params[(id)kSecMatchLimit] = (id)kSecMatchLimitAll;
	// params[(id)kSecAttrApplicationTag] = (id)appTag;

	st = SecItemCopyMatching((__bridge CFDictionaryRef)params, (const void **)&data);
	if (st != 0) {
		err = CFErrorCreate(kCFAllocatorDefault,
			kCFErrorDomainOSStatus,
			st,
			NULL);
		goto cleanup;
	}

	CFIndex count = CFArrayGetCount(data);
	for (long i = 0; i < count; ++i) {
		SecKeyRef privateKey = (SecKeyRef)CFArrayGetValueAtIndex(data, i);
		SecKeyRef publicKey = SecKeyCopyPublicKey(privateKey);
		if (publicKey == nil) {
			continue;
		}
		CFRetain(privateKey);

		dpop_enclave_list_item_t *item = calloc(1, sizeof(dpop_enclave_list_item_t));
		item->privateKey = privateKey;
		item->publicKey = publicKey;
		item->next = rv->items;
		rv->items = item;
	}

cleanup:
	if (err != nil) {
		rv->err = err;
	}
	if (params != nil) {
		CFRelease(params);
	}
	if (data != nil) {
		CFRelease(data);
	}
	if (appTag != nil) {
		CFRelease(appTag);
	}
}

void dpop_enclave_list_result_free(dpop_enclave_list_result_t *lr) {
	if (lr->err != nil) {
		CFRelease(lr->err);
	}
	dpop_enclave_list_item_t *item = lr->items;
	while (item != NULL) {
		dpop_enclave_list_item_t *last = item;

		CFRelease(item->privateKey);
		CFRelease(item->publicKey);

		item = item->next;
		free(last);
	}

	free(lr);
}

*/
import "C"
import (
	"fmt"
	"unsafe"
)

func list_keypairs(app string) ([]Keypair, error) {
	var p C.dpop_enclave_list_params_t
	p.app = C.CString(app)
	defer C.free(unsafe.Pointer(p.app))

	var rv *C.dpop_enclave_list_result_t

	C.dpop_enclave_list(&p, &rv)
	defer C.dpop_enclave_list_result_free(rv)
	if rv.err != 0 {
		err := fmt.Errorf("dpop_enclave_list: failed: %s", cfErrToStr(rv.err))
		return nil, err
	}
	rl := make([]Keypair, 0)

	for item := rv.items; item != nil; item = item.next {
		kp, err := newKeypair(item.publicKey, item.privateKey)
		// C.CFShow((C.CFTypeRef)(item.publicKey))
		// C.CFShow((C.CFTypeRef)(item.privateKey))
		// C.CFShow((C.CFTypeRef)(C.SecKeyCopyAttributes(item.privateKey)))
		if err != nil {
			continue
		}
		rl = append(rl, kp)
	}
	return rl, nil
}
