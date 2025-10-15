package c_polygonid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	jweProvider "github.com/iden3/iden3comm/v2/packers/providers/jwe"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type anonPackerInput struct {
	Message          json.RawMessage          `json:"message"`
	RecipientDidDocs []document.DidResolution `json:"recipientDidDocs"`
	RecipientAlg     map[string]string        `json:"recipientAlg,omitempty"`
}

func (a *anonPackerInput) getAlgForRecipient(did string) string {
	if a.RecipientAlg != nil {
		if alg, ok := a.RecipientAlg[did]; ok {
			return alg
		}
	}
	return jwa.RSA_OAEP_256().String()
}

func (a *anonPackerInput) validate() error {
	if len(a.Message) == 0 {
		return fmt.Errorf("message is required")
	}
	if len(a.RecipientDidDocs) == 0 {
		return fmt.Errorf("at least one recipient DID document is required")
	}
	// validate if each resolution document has a DID document
	for _, d := range a.RecipientDidDocs {
		if d.DidDocument == nil {
			return fmt.Errorf("DID document is required in each resolution document")
		}
	}
	return nil
}

type anonUnpackerInput struct {
	Ciphertext json.RawMessage `json:"ciphertext"`
	KeySet     json.RawMessage `json:"keySet"`
}

func (a *anonUnpackerInput) validate() error {
	if len(a.Ciphertext) == 0 {
		return fmt.Errorf("ciphertext is required")
	}
	if len(a.KeySet) == 0 {
		return fmt.Errorf("keySet is required")
	}
	return nil
}

// AnonPack performs anonymous encryption of a message for multiple recipients.
func AnonPack(in []byte) ([]byte, error) {
	var encInfo anonPackerInput
	err := json.Unmarshal(in, &encInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal input: %w", err)
	}
	err = encInfo.validate()
	if err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	didDocResolverFn := func(ctx context.Context, did string, opts *services.ResolverOpts) (*document.DidResolution, error) {
		for _, dr := range encInfo.RecipientDidDocs {
			if dr.DidDocument.ID == did {
				return &dr, nil
			}
		}
		return nil, fmt.Errorf("DID document not found: %s", did)
	}

	pm := iden3comm.NewPackageManager()
	err = pm.RegisterPackers(packers.NewAnoncryptPacker(nil, didDocResolverFn))
	if err != nil {
		return nil, fmt.Errorf("failed to register packer: %w", err)
	}

	recipientDids := make([]packers.AnoncryptRecipients, 0, len(encInfo.RecipientDidDocs))
	for _, r := range encInfo.RecipientDidDocs {
		recipientDids = append(recipientDids, packers.AnoncryptRecipients{
			DID:    r.DidDocument.ID,
			JWKAlg: encInfo.getAlgForRecipient(r.DidDocument.ID),
		})
	}

	ciphertext, err := pm.Pack(packers.MediaTypeEncryptedMessage, encInfo.Message, packers.AnoncryptPackerParams{
		Recipients: recipientDids,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to pack message: %w", err)
	}
	return ciphertext, nil
}

// AnonUnpack performs decryption of an anonymously encrypted message using the provided key set.
func AnonUnpack(in []byte) ([]byte, error) {
	var decInfo anonUnpackerInput
	err := json.Unmarshal(in, &decInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal input: %w", err)
	}
	err = decInfo.validate()
	if err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	keySet, err := jwk.Parse(decInfo.KeySet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key set: %w", err)
	}

	resolveKeyFn := func(_ string) (interface{}, error) {
		if keySet.Len() != 1 {
			return nil, errors.New("key set must contain exactly one key")
		}
		key, ok := keySet.Key(0)
		if !ok || key == nil {
			return nil, errors.New("key idx: 0 not found in key set")
		}
		return key, nil
	}

	pm := iden3comm.NewPackageManager()
	err = pm.RegisterPackers(packers.NewAnoncryptPacker(resolveKeyFn, nil))
	if err != nil {
		return nil, fmt.Errorf("failed to register packer: %w", err)
	}

	plaintext, mt, err := pm.Unpack(decInfo.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack message: %w", err)
	}

	if plaintext.Typ != mt {
		return nil, fmt.Errorf(
			"incorrect message type. In message: '%s'; from packer: '%s'", plaintext.Typ, mt)
	}

	pb, err := json.Marshal(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal plaintext: %w", err)
	}

	return pb, nil
}

// DecryptJWE decrypts a JWE ciphertext using the provided key set.
func DecryptJWE(in []byte) ([]byte, error) {
	var decInfo anonUnpackerInput
	err := json.Unmarshal(in, &decInfo)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal input: %w", err)
	}
	err = decInfo.validate()
	if err != nil {
		return nil, fmt.Errorf("invalid input: %w", err)
	}

	keySet, err := jwk.Parse(decInfo.KeySet)
	if err != nil {
		return nil, fmt.Errorf("failed to parse key set: %w", err)
	}

	if keySet.Len() != 1 {
		return nil, errors.New("key set must contain exactly one key")
	}

	key, ok := keySet.Key(0)
	if !ok || key == nil {
		return nil, errors.New("key idx: 0 not found in key set")
	}

	keyResolutionFn := func(_ string) (interface{}, error) {
		return key, nil
	}

	return jweProvider.Decrypt(decInfo.Ciphertext, keyResolutionFn)
}
