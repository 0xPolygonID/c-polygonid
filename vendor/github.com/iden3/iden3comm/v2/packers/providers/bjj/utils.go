package bjj

import (
	"crypto"
	"encoding/hex"
	"errors"
	"io"
	"math/big"

	bjj "github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/lestrrat-go/jwx/v2/jwk"
)

// ParseKey parses jwk key to bjj public key
func ParseKey(jwkKey jwk.Key) (*bjj.PublicKey, error) {
	ux, ok := jwkKey.Get("x")
	if !ok {
		return nil, errors.New("can't find x")
	}
	uy, _ := jwkKey.Get("y")
	if !ok {
		return nil, errors.New("can't find y")
	}
	x := big.NewInt(0).SetBytes(ux.([]byte))
	y := big.NewInt(0).SetBytes(uy.([]byte))

	bjjPoint := bjj.Point{X: x, Y: y}
	if !bjjPoint.InCurve() {
		return nil, errors.New("point is not in curve")
	}
	pubKey := bjj.PublicKey(bjjPoint)

	return &pubKey, nil
}

// GoSigner implements crypto.Signer interface
type GoSigner struct {
	pk *bjj.PrivateKey
}

// Public returns nil because we don't need it
func (s *GoSigner) Public() crypto.PublicKey {
	return nil
}

// Sign signs the digest with the private key
func (s *GoSigner) Sign(_ io.Reader, buf []byte, _ crypto.SignerOpts) ([]byte, error) {
	digest := big.NewInt(0).SetBytes(buf)
	compressed := s.pk.SignPoseidon(digest).Compress()

	sig, err := compressed.MarshalText()
	if err != nil {
		return nil, err
	}
	return sig, nil
}

// GoSignerFromPrivHex creates GoSigner from hex encoded private key
func GoSignerFromPrivHex(h string) (*GoSigner, error) {
	rawPK, err := hex.DecodeString(h)
	if err != nil {
		return nil, err
	}
	if len(rawPK) != 32 {
		return nil, errors.New("invalid private key length")
	}

	var pk bjj.PrivateKey
	copy(pk[:], rawPK)

	return &GoSigner{&pk}, nil
}
