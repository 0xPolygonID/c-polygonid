package gocircuitexternal

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
)

func reverseBytes(data []byte) []byte {
	reversed := make([]byte, len(data))
	for i := range data {
		reversed[i] = data[len(data)-1-i]
	}
	return reversed
}

// golang implementation of the splitToWords from AnonAadhaar utils
// https://github.com/anon-aadhaar/anon-aadhaar/blob/e0cbde3d8e4a3969a6e44a2999ec539439e61d58/packages/core/src/utils.ts#L21
func splitToWords(number, wordsize, numberElement *big.Int) ([]*big.Int, error) {
	t := new(big.Int).Set(number)
	words := []*big.Int{}

	power := new(big.Int).Exp(big.NewInt(2), wordsize, nil)
	for i := big.NewInt(0); i.Cmp(numberElement) < 0; i.Add(i, big.NewInt(1)) {
		mod := new(big.Int).Mod(t, power)
		words = append(words, mod)
		t.Div(t, power)
	}

	if t.Cmp(big.NewInt(0)) != 0 {
		return nil, fmt.Errorf("number %s does not fit in %d bits", number.String(), new(big.Int).Mul(wordsize, numberElement).Uint64())
	}

	return words, nil
}

// convert a PEM encoded key to a JWK
func pemToJWK(content []byte) (jwk.Key, error) {
	key, _, err := jwk.NewPEMDecoder().Decode(content)
	if err != nil {
		return nil, err
	}
	return jwk.Import(key)
}

func extractNfromPubKey(content []byte) (*big.Int, error) {
	key, err := pemToJWK(content)
	if err != nil {
		return nil, err
	}
	var n []byte
	if err := key.Get("n", &n); err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(n), nil
}

func toString(b []*big.Int) []string {
	v := make([]string, len(b))
	for i := range b {
		v[i] = b[i].String()
	}
	return v
}

func mustBigInt(s string) *big.Int {
	i, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic(fmt.Sprintf("failed to parse big.Int: %s", s))
	}
	return i
}

func int64ToBytes(value int64) []byte {
	buf := new(bytes.Buffer)
	_ = binary.Write(buf, binary.BigEndian, value)
	return buf.Bytes()
}

func uint8ArrayToCharArray(a []uint8) []string {
	charArray := make([]string, len(a))
	for i, v := range a {
		charArray[i] = strconv.Itoa(int(v))
	}
	return charArray
}

func isTimeUnderPrime(t time.Time) error {
	var x = new(big.Int).Mul(
		big.NewInt(t.Unix()),
		big.NewInt(1_000_000_000),
	)
	x.Add(x, big.NewInt(int64(t.Nanosecond())))

	expirationDateHash, err := hashvalue(t)
	if err != nil {
		return err
	}
	if expirationDateHash.Cmp(x) != 0 {
		return errors.New("expiration date is not fit to prime number")
	}
	return nil
}
