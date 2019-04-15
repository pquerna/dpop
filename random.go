package dpop

import (
	crand "crypto/rand"
	"math/big"
)

const randLetters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

type rfunc func(int64) int64

func randStringFM(sourceData string, n int, rfn rfunc) string {
	data := make([]byte, n)

	l := int64(len(sourceData))

	for i, _ := range data {
		v := rfn(l)
		data[i] = sourceData[v]
	}

	return string(data)
}

func crandInt64n(n int64) int64 {
	v, err := crand.Int(crand.Reader, big.NewInt(n))
	if err != nil {
		panic(err)
	}
	return v.Int64()

}

func randCryptoString(n int) string {
	return randStringFM(randLetters, n, crandInt64n)
}
