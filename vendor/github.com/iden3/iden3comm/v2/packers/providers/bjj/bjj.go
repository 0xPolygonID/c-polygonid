package bjj

import (
	"crypto"
	"crypto/rand"
	"errors"
	"fmt"

	bjj "github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/lestrrat-go/jwx/v2/jwa"
)

// Alg signature algorithm
const Alg jwa.SignatureAlgorithm = "BJJ"

// Provider is a signer and verifier for BJJ
type Provider struct{}

// Algorithm returns BJJAlg
func (p *Provider) Algorithm() jwa.SignatureAlgorithm {
	return Alg
}

// Sign signs payload with BJJ private key
func (p *Provider) Sign(payload []byte, opts interface{}) ([]byte, error) {
	signer, ok := opts.(crypto.Signer)
	if !ok {
		return nil, errors.New("bjj signer opts support only signer interface")
	}

	digest, err := poseidon.HashBytes(payload)
	if err != nil {
		return nil, fmt.Errorf("failed get poseidon hash for payload: %v", err)
	}

	sig, err := signer.Sign(rand.Reader, digest.Bytes(), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to sign payload: %v", err)
	}

	return sig, nil
}

// Verify verifies signature with BJJ public key
func (p *Provider) Verify(payload, signature []byte, opts interface{}) error {
	var bjjPubKey *bjj.PublicKey
	// we can expande opts here
	switch v := opts.(type) {
	case *bjj.PublicKey:
		bjjPubKey = v
	case bjj.PublicKey:
		bjjPubKey = &v
	default:
		return errors.New("provide bjj public key for verification signature")
	}

	if !bjjPubKey.Point().InCurve() {
		return errors.New("public key is not on curve")
	}

	digest, err := poseidon.HashBytes(payload)
	if err != nil {
		return fmt.Errorf("failed get poseidon hash for payload: %v", err)
	}
	poseidonComSig := &bjj.SignatureComp{}
	if err = poseidonComSig.UnmarshalText(signature); err != nil {
		return fmt.Errorf("can't unmarshal bjj signature: %v", err)
	}
	poseidonDecSig, err := poseidonComSig.Decompress()
	if err != nil {
		return fmt.Errorf("can't decompress bjj signature: %v", err)
	}

	if !bjjPubKey.VerifyPoseidon(digest, poseidonDecSig) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}
