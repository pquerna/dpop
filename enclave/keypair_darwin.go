// +build darwin

package enclave

/*
#cgo CFLAGS: -x objective-c
#cgo LDFLAGS: -lobjc -framework Security
#import <Security/Security.h>

typedef struct dpop_enclave_sign_params_t {
	SecKeyRef key;
	CFDataRef input;
} dpop_enclave_sign_params_t;

typedef struct dpop_enclave_sign_result_t {
	CFErrorRef err;
	CFDataRef output;
} dpop_enclave_sign_result_t;

void dpop_enclave_sign(dpop_enclave_sign_params_t *p, dpop_enclave_sign_result_t **out) {
	CFErrorRef err = NULL;
	CFDataRef output = NULL;
	dpop_enclave_sign_result_t *rv = NULL;

	rv = calloc(1, sizeof(dpop_enclave_sign_result_t));
	*out = rv;

	// fprintf(stderr, "SecKeyGetBlockSize(): %zd\n", SecKeyGetBlockSize(p->key));
	// fprintf(stderr, "SecKeyIsAlgorithmSupported(kSecKeyAlgorithmECDSASignatureDigestX962SHA256): %s\n", SecKeyIsAlgorithmSupported(p->key, kSecKeyOperationTypeSign, kSecKeyAlgorithmECDSASignatureDigestX962SHA256) ? "true" : "false");

	output = SecKeyCreateSignature(p->key, kSecKeyAlgorithmECDSASignatureDigestX962SHA256, p->input, &err);

	if (err != nil) {
		goto cleanup;
	}

	rv->output = output;
	output = nil;

cleanup:
	if (err != nil) {
		rv->err = err;
	}
	if (output != nil) {
		CFRelease(output);
	}
}

void dpop_enclave_sign_result_free(dpop_enclave_sign_result_t *sr) {
	if (sr->err != nil) {
		CFRelease(sr->err);
	}
	if (sr->output != nil) {
		CFRelease(sr->output);
	}
	free(sr);
}

*/
import "C"

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"fmt"
	"io"
	"runtime"
	"unsafe"
)

type keypair struct {
	publicKey  C.SecKeyRef
	privateKey C.SecKeyRef
	label      string
	app        string
	pub        *ecdsa.PublicKey
}

func newKeypair(publicKey C.SecKeyRef, privateKey C.SecKeyRef) (*keypair, error) {
	C.CFRetain((C.CFTypeRef)(publicKey))
	C.CFRetain((C.CFTypeRef)(privateKey))

	rv := &keypair{
		publicKey:  publicKey,
		privateKey: privateKey,
	}

	runtime.SetFinalizer(rv, keypairFinalizer)

	var xerr C.CFErrorRef
	data := C.SecKeyCopyExternalRepresentation(rv.publicKey, &xerr)
	if xerr != 0 {
		return nil, fmt.Errorf("dpop_enclave: SecKeyCopyExternalRepresentation failed: %s", cfErrToStr(xerr))
	}
	defer C.CFRelease((C.CFTypeRef)(data))
	ecData := cfDataToBytes(data)

	// TODO(pquerna): detect from key attributes it's type, etc
	crv := elliptic.P256()

	x, y := elliptic.Unmarshal(crv, ecData)
	rv.pub = &ecdsa.PublicKey{
		Curve: crv,
		X:     x,
		Y:     y,
	}

	attrs := C.SecKeyCopyAttributes(privateKey)
	defer C.CFRelease((C.CFTypeRef)(attrs))

	found := C.CFDictionaryGetValue(attrs, (unsafe.Pointer)(C.kSecAttrLabel))
	if found != nil {
		rv.label = cfstrToStr((C.CFStringRef)(found))
	}

	found = C.CFDictionaryGetValue(attrs, (unsafe.Pointer)(C.kSecAttrApplicationTag))
	if found != nil {
		rv.app = string(cfDataToBytes((C.CFDataRef)(found)))
	}

	return rv, nil
}

func keypairFinalizer(kp *keypair) {
	if kp.publicKey != 0 {
		C.CFRelease((C.CFTypeRef)(kp.publicKey))
		kp.publicKey = 0
	}
	if kp.privateKey != 0 {
		C.CFRelease((C.CFTypeRef)(kp.privateKey))
		kp.privateKey = 0
	}
}

func (kp *keypair) Public() crypto.PublicKey {
	return kp.pub
}

func (kp *keypair) Label() string {
	return kp.label
}

func (kp *keypair) ID() string {
	return kp.app
}

// Sign signs digest with the private key, possibly using entropy from
// rand. For an RSA key, the resulting signature should be either a
// PKCS#1 v1.5 or PSS signature (as indicated by opts). For an (EC)DSA
// key, it should be a DER-serialised, ASN.1 signature structure.
//
// Hash implements the SignerOpts interface and, in most cases, one can
// simply pass in the hash function used as opts. Sign may also attempt
// to type assert opts to other types in order to obtain algorithm
// specific values. See the documentation in each package for details.
//
// Note that when a signature of a hash of a larger message is needed,
// the caller is responsible for hashing the larger message and passing
// the hash (as digest) and the hash function (as opts) to Sign.
func (kp *keypair) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	var sr *C.dpop_enclave_sign_result_t
	var p C.dpop_enclave_sign_params_t

	// ES256             | ECDSA using P-256 and SHA-256
	// algorithm := C.kSecKeyAlgorithmECDSASignatureDigestX962SHA256

	input := bytesToCFData(digest)
	defer C.CFRelease((C.CFTypeRef)(input))

	p.input = input
	p.key = kp.privateKey

	C.dpop_enclave_sign(&p, &sr)
	defer C.dpop_enclave_sign_result_free(sr)
	if sr.err != 0 {
		err := fmt.Errorf("dpop_enclave_sign: failed: %s", cfErrToStr(sr.err))
		return nil, err
	}

	return cfDataToBytes(sr.output), nil
}
