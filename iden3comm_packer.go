package c_polygonid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/iden3/driver-did-iden3/pkg/document"
	"github.com/iden3/driver-did-iden3/pkg/services"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	jweProvider "github.com/iden3/iden3comm/v2/packers/providers/jwe"
	"github.com/iden3/iden3comm/v2/protocol"
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

type encryptedCredentialInput struct {
	EncryptedCredentialIssuanceMessage protocol.EncryptedCredentialIssuanceMessage `json:"encryptedCredentialIssuanceMessage"`
	KeySet                             json.RawMessage                             `json:"keySet"`
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
	return decrypt(decInfo)
}

// DecryptEncryptedCredential decrypts and verifies a W3C credential in JWE format.
func DecryptEncryptedCredential(ctx context.Context, cfg EnvConfig, in []byte) ([]byte, error) {
	var msg encryptedCredentialInput
	err := json.Unmarshal(in, &msg)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal encrypted credential issuance message: %w", err)
	}

	jweBytes, err := json.Marshal(msg.EncryptedCredentialIssuanceMessage.Body.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JWE data: %w", err)
	}

	decryptIn := anonUnpackerInput{
		Ciphertext: jweBytes,
		KeySet:     msg.KeySet,
	}
	w3cCredentialBytes, err := decrypt(decryptIn)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt credential: %w", err)
	}

	var credential verifiable.W3CCredential
	err = json.Unmarshal(w3cCredentialBytes, &credential)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential: %w", err)
	}

	err = verifyIntegrity(ctx, cfg, credential, msg.EncryptedCredentialIssuanceMessage.Body)
	if err != nil {
		return nil, fmt.Errorf("credential integrity verification failed: %w", err)
	}

	return w3cCredentialBytes, nil
}

type VerifyProofResponse struct {
	Valid bool `json:"valid"`
}

// VerifyProof verifies the proofs of a W3C credential.
// The function returns an error indicating the result of the verification.
func VerifyProof(ctx context.Context, cfg EnvConfig, credentialBytes []byte) (VerifyProofResponse, error) {
	var credential verifiable.W3CCredential
	err := json.Unmarshal(credentialBytes, &credential)
	if err != nil {
		return VerifyProofResponse{}, fmt.Errorf("failed to unmarshal credential: %w", err)
	}
	return verifyProof(ctx, cfg, credential)
}

func verifyIntegrity(ctx context.Context, cfg EnvConfig, credential verifiable.W3CCredential, encryptedCredential protocol.EncryptedIssuanceMessageBody) error {
	if credential.ID !=
		fmt.Sprintf("urn:uuid:%s", encryptedCredential.ID) {
		return fmt.Errorf("credential ID does not match encrypted issuance message ID")
	}
	if !arrayContainsString(credential.Context, encryptedCredential.Context) {
		return fmt.Errorf("credential context does not contain encrypted issuance message context")
	}
	if !arrayContainsString(credential.Type, encryptedCredential.Type) {
		return fmt.Errorf("credential type does not contain encrypted issuance message type")
	}

	// set proof from the encrypted credential issuance message to w3c credential
	credential.Proof = encryptedCredential.Proof
	_, err := verifyProof(ctx, cfg, credential)
	if err != nil {
		return fmt.Errorf("failed to verify credential proof: %w", err)
	}

	return nil
}

type wrapper func(cs verifiable.CredentialStatus) (verifiable.RevocationStatus, error)

func (f wrapper) Resolve(ctx context.Context,
	credentialStatus verifiable.CredentialStatus) (verifiable.RevocationStatus, error) {
	return f(credentialStatus)
}

// verifyProof verifies the proofs of a W3C credential.
func verifyProof(ctx context.Context, cfg EnvConfig, credential verifiable.W3CCredential) (VerifyProofResponse, error) {
	proofsToVerify := make([]verifiable.ProofType, 0, len(credential.Proof))
	for _, p := range credential.Proof {
		proofsToVerify = append(proofsToVerify, p.ProofType())
	}

	userDidStr, ok := credential.CredentialSubject["id"].(string)
	if !ok {
		return VerifyProofResponse{}, fmt.Errorf("credential subject ID is missing or not a string")
	}

	userDID, err := w3c.ParseDID(userDidStr)
	if err != nil {
		return VerifyProofResponse{}, fmt.Errorf("failed to parse user DID: %w", err)
	}

	issuerDID, err := w3c.ParseDID(credential.Issuer)
	if err != nil {
		return VerifyProofResponse{}, fmt.Errorf("failed to parse issuer DID: %w", err)
	}

	fn := func(cs verifiable.CredentialStatus) (verifiable.RevocationStatus, error) {
		return cachedResolve(ctx, cfg, issuerDID, userDID, cs, getResolversRegistry)
	}

	universalResolverHTTPClient := verifiable.NewHTTPDIDResolver(cfg.DIDResolverURL)

	defaultResolver := verifiable.DefaultCredentialStatusResolverRegistry
	defaultResolver.Register(verifiable.SparseMerkleTreeProof, wrapper(fn))
	defaultResolver.Register(verifiable.Iden3ReverseSparseMerkleTreeProof, wrapper(fn))
	defaultResolver.Register(verifiable.Iden3commRevocationStatusV1, wrapper(fn))
	defaultResolver.Register(verifiable.Iden3OnchainSparseMerkleTreeProof2023, wrapper(fn))

	dl := cfg.documentLoader()
	for _, proofTypeToVerify := range proofsToVerify {
		if err := credential.VerifyProof(
			ctx,
			proofTypeToVerify,
			universalResolverHTTPClient,
			verifiable.WithStatusResolverRegistry(defaultResolver),
			verifiable.WithMerklizeOptions(merklize.WithDocumentLoader(dl)),
		); err != nil {
			return VerifyProofResponse{}, fmt.Errorf("failed to verify proof of type %s: %w", proofTypeToVerify, err)
		}
	}

	return VerifyProofResponse{Valid: true}, nil
}

func decrypt(decInfo anonUnpackerInput) ([]byte, error) {
	err := decInfo.validate()
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

func arrayContainsString(arr []string, str string) bool {
	for _, a := range arr {
		if a == str {
			return true
		}
	}
	return false
}
