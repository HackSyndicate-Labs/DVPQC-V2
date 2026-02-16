package falconreal

/*
#cgo CFLAGS: -I/home/arthas/proyecto/damvuln-pqc-labs/external/pqclean/crypto_sign/falcon-512/clean
#cgo LDFLAGS:

#include "api.h"
#include <stdlib.h>
*/
import "C"
import (
	"errors"
)

func Keypair() ([]byte, []byte, error) {

	pub := make([]byte, C.PQCLEAN_FALCON512_CLEAN_CRYPTO_PUBLICKEYBYTES)
	priv := make([]byte, C.PQCLEAN_FALCON512_CLEAN_CRYPTO_SECRETKEYBYTES)

	r := C.PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(
		(*C.uchar)(&pub[0]),
		(*C.uchar)(&priv[0]),
	)

	if r != 0 {
		return nil, nil, errors.New("falcon keypair failed")
	}

	return pub, priv, nil
}

func Sign(msg []byte, priv []byte) ([]byte, error) {

	sig := make([]byte, C.PQCLEAN_FALCON512_CLEAN_CRYPTO_BYTES)
	var siglen C.size_t

	r := C.PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(
		(*C.uchar)(&sig[0]),
		&siglen,
		(*C.uchar)(&msg[0]),
		C.ulong(len(msg)),
		(*C.uchar)(&priv[0]),
	)

	if r != 0 {
		return nil, errors.New("falcon sign failed")
	}

	return sig[:siglen], nil
}

func Verify(msg []byte, sig []byte, pub []byte) bool {

	r := C.PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(
		(*C.uchar)(&sig[0]),
		C.ulong(len(sig)),
		(*C.uchar)(&msg[0]),
		C.ulong(len(msg)),
		(*C.uchar)(&pub[0]),
	)

	return r == 0
}
