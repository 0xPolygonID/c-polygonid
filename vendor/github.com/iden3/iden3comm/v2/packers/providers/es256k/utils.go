package es256k

import (
	"crypto/ecdsa"
	"math/big"

	"github.com/dustinxie/ecc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/pkg/errors"
)

// ParseKey parses jwk key to ecdsa public key
func ParseKey(jwkKey jwk.Key) (*ecdsa.PublicKey, error) {
	x, ok := jwkKey.Get("x")
	if !ok {
		return nil, errors.New("can't find x")
	}
	y, ok := jwkKey.Get("y")
	if !ok {
		return nil, errors.New("can't find y")
	}
	bgx := new(big.Int).SetBytes(x.([]byte))
	bgy := new(big.Int).SetBytes(y.([]byte))

	pub := ecdsa.PublicKey{
		Curve: ecc.P256k1(),
		X:     bgx,
		Y:     bgy,
	}

	if !pub.IsOnCurve(pub.X, pub.Y) {
		return nil, errors.New("ecdsa public key is not on curve (secp256k1)")
	}

	return &pub, nil
}

// PrivateKeyFromHex creates ecdsa private key from hex encoded private key
func PrivateKeyFromHex(h string) (*ecdsa.PrivateKey, error) {
	D, err := big.NewInt(0).SetString(
		h, 16,
	)
	if !err {
		return nil, errors.Errorf("invalid hex string '%s'", h)
	}
	return &ecdsa.PrivateKey{
		D: D,
		PublicKey: ecdsa.PublicKey{
			Curve: ecc.P256k1(),
		},
	}, nil
}

// NewECDSA creates ecdsa public key from encoded key
func NewECDSA(encodedKey []byte) ecdsa.PublicKey {
	return ecdsa.PublicKey{
		Curve: ecc.P256k1(),
		X:     new(big.Int).SetBytes(encodedKey[:32]),
		Y:     new(big.Int).SetBytes(encodedKey[32:]),
	}
}
