package verifiable

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"time"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/utils"
	"github.com/pkg/errors"
)

// W3CCredential is struct that represents claim json-ld document
type W3CCredential struct {
	ID string `json:"id,omitempty"`

	Context           []string               `json:"@context"`
	Type              []string               `json:"type"`
	Expiration        *time.Time             `json:"expirationDate,omitempty"`
	IssuanceDate      *time.Time             `json:"issuanceDate,omitempty"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	CredentialStatus  interface{}            `json:"credentialStatus,omitempty"`
	Issuer            string                 `json:"issuer"`
	CredentialSchema  CredentialSchema       `json:"credentialSchema"`
	Proof             CredentialProofs       `json:"proof,omitempty"`
	RefreshService    *RefreshService        `json:"refreshService,omitempty"`
	DisplayMethod     *DisplayMethod         `json:"displayMethod,omitempty"`
}

// VerifyProof verify credential proof
func (vc *W3CCredential) VerifyProof(ctx context.Context, proofType ProofType,
	didResolver DIDResolver, opts ...W3CProofVerificationOpt) error {

	verifyConfig := w3CProofVerificationConfig{}
	for _, o := range opts {
		o(&verifyConfig)
	}

	var credProof CredentialProof
	for _, p := range vc.Proof {
		if p.ProofType() == proofType {
			credProof = p
			break
		}
	}
	if credProof == nil {
		return ErrProofNotFound
	}

	coreClaim, err := credProof.GetCoreClaim()
	if err != nil {
		return errors.New("can't get core claim")
	}

	err = vc.verifyCredentialCoreClaim(ctx, coreClaim, verifyConfig.merklizeOptions)
	if err != nil {
		return errors.WithStack(err)
	}

	switch proofType {
	case BJJSignatureProofType:
		var proof BJJSignatureProof2021
		err = remarshalObj(&proof, credProof)
		if err != nil {
			return err
		}
		return verifyBJJSignatureProof(ctx, proof, coreClaim, didResolver,
			verifyConfig)
	case Iden3SparseMerkleTreeProofType:
		var proof Iden3SparseMerkleTreeProof
		err = remarshalObj(&proof, credProof)
		if err != nil {
			return err
		}
		return verifyIden3SparseMerkleTreeProof(ctx, proof, coreClaim,
			didResolver)
	default:
		return ErrProofNotSupported
	}
}

func (vc *W3CCredential) verifyCredentialCoreClaim(ctx context.Context, proofCoreClaim *core.Claim, merklizeOptions []merklize.MerklizeOption) error {
	merklizedPosition, err := proofCoreClaim.GetMerklizedPosition()
	if err != nil {
		return errors.New("can't get core claim merklized position")
	}
	var merklizedPositionString string
	switch merklizedPosition {
	case core.MerklizedRootPositionNone:
		merklizedPositionString = CredentialMerklizedRootPositionNone
	case core.MerklizedRootPositionIndex:
		merklizedPositionString = CredentialMerklizedRootPositionIndex
	case core.MerklizedRootPositionValue:
		merklizedPositionString = CredentialMerklizedRootPositionValue
	}

	idPosition, err := proofCoreClaim.GetIDPosition()
	if err != nil {
		return errors.New("can't get core claim id position")
	}

	var subjectPositionString string
	switch idPosition {
	case core.IDPositionNone:
		subjectPositionString = ""
	case core.IDPositionIndex:
		subjectPositionString = CredentialSubjectPositionIndex
	case core.IDPositionValue:
		subjectPositionString = CredentialSubjectPositionValue
	}

	coreClaimOpts := CoreClaimOptions{
		RevNonce:              proofCoreClaim.GetRevocationNonce(),
		Version:               proofCoreClaim.GetVersion(),
		SubjectPosition:       subjectPositionString,
		MerklizedRootPosition: merklizedPositionString,
		Updatable:             proofCoreClaim.GetFlagUpdatable(),
		MerklizerOpts:         merklizeOptions,
	}
	credentialClaim, err := vc.ToCoreClaim(ctx, &coreClaimOpts)
	if err != nil {
		return errors.WithStack(err)
	}

	coreClaimHex, err := proofCoreClaim.Hex()
	if err != nil {
		return errors.New("can't get core claim hex")
	}

	credentialClaimHex, err := credentialClaim.Hex()
	if err != nil {
		return errors.New("can't get credential claim hex")
	}

	if coreClaimHex != credentialClaimHex {
		return errors.New("proof generated for another credential")
	}

	return nil
}

func verifyBJJSignatureProof(ctx context.Context, proof BJJSignatureProof2021,
	coreClaim *core.Claim, didResolver DIDResolver,
	verifyConfig w3CProofVerificationConfig) error {

	// issuer's claim with public key
	authClaim, err := proof.IssuerData.authClaim()
	if err != nil {
		return err
	}

	// core claim's signature
	sig, err := bjjSignatureFromHexString(proof.Signature)
	if err != nil || sig == nil {
		return err
	}

	err = verifyClaimSignature(coreClaim, sig, authClaim)
	if err != nil {
		return err
	}

	issuerDID, err := w3c.ParseDID(proof.IssuerData.ID)
	if err != nil {
		return err
	}

	issuerStateHash, err := merkletree.NewHashFromHex(*proof.IssuerData.State.Value)
	if err != nil {
		return fmt.Errorf("invalid state formant: %v", err)
	}

	issuerDID.Query = fmt.Sprintf("state=%s", issuerStateHash.Hex())

	didDoc, err := didResolver.Resolve(ctx, issuerDID)
	if err != nil {
		return err
	}

	vm, err := getIden3StateInfo2023FromDIDDocument(didDoc)
	if err != nil {
		return err
	}

	// Published or genesis
	if !*vm.IdentityState.Published {
		var (
			isGenesisState bool
			issuerID       core.ID
		)
		issuerID, err = core.IDFromDID(*issuerDID)
		if err != nil {
			return err
		}
		isGenesisState, err = core.CheckGenesisStateID(issuerID.BigInt(), issuerStateHash.BigInt())
		if err != nil {
			return err
		}
		if !isGenesisState {
			return errors.New("issuer state not published and not genesis")
		}
	}

	err = validateAuthClaimRevocation(ctx, proof.IssuerData,
		verifyConfig.credStatusValidationOpts...)
	if err != nil {
		return err
	}

	return err
}

func verifyClaimSignature(claim *core.Claim, sig *babyjub.Signature,
	authClaim *core.Claim) error {

	publicKey := publicKeyFromClaim(authClaim)

	// core claim hash
	hi, hv, err := claim.HiHv()
	if err != nil {
		return err
	}

	claimHash, err := poseidon.Hash([]*big.Int{hi, hv})
	if err != nil {
		return err
	}

	valid := publicKey.VerifyPoseidon(claimHash, sig)
	if !valid {
		return errors.New("claim signature validation failed")
	}
	return nil
}

func publicKeyFromClaim(claim *core.Claim) *babyjub.PublicKey {
	rawSlotInts := claim.RawSlotsAsInts()
	var publicKey babyjub.PublicKey
	publicKey.X = rawSlotInts[2] // Ax should be in indexSlotA
	publicKey.Y = rawSlotInts[3] // Ay should be in indexSlotB
	return &publicKey
}

func validateAuthClaimRevocation(ctx context.Context, issuerData IssuerData,
	opts ...CredentialStatusValidationOption) error {
	credStatus, err := coerceCredentialStatus(issuerData.CredentialStatus)
	if err != nil {
		return err
	}

	authClaim, err := issuerData.authClaim()
	if err != nil {
		return err
	}

	if credStatus.RevocationNonce != authClaim.GetRevocationNonce() {
		return fmt.Errorf("revocation nonce mismatch: credential revocation "+
			"nonce (%v) != auth claim revocation nonce (%v)",
			credStatus.RevocationNonce, authClaim.GetRevocationNonce())
	}

	_, err = ValidateCredentialStatus(ctx, *credStatus, opts...)
	return err
}

func verifyIden3SparseMerkleTreeProof(ctx context.Context,
	proof Iden3SparseMerkleTreeProof, coreClaim *core.Claim,
	didResolver DIDResolver) error {

	var err error

	issuerDID, err := w3c.ParseDID(proof.IssuerData.ID)
	if err != nil {
		return err
	}

	issuerStateHash, err := merkletree.NewHashFromHex(*proof.IssuerData.State.Value)
	if err != nil {
		return fmt.Errorf("invalid state formant: %v", err)
	}

	issuerDID.Query = fmt.Sprintf("state=%s", issuerStateHash.Hex())

	didDoc, err := didResolver.Resolve(ctx, issuerDID)
	if err != nil {
		return err
	}

	vm, err := getIden3StateInfo2023FromDIDDocument(didDoc)
	if err != nil {
		return err
	}

	// Published or genesis
	if !*vm.IdentityState.Published {
		var (
			isGenesisState bool
			issuerID       core.ID
		)
		issuerID, err = core.IDFromDID(*issuerDID)
		if err != nil {
			return err
		}
		isGenesisState, err = core.CheckGenesisStateID(issuerID.BigInt(), issuerStateHash.BigInt())
		if err != nil {
			return err
		}
		if !isGenesisState {
			return errors.New("issuer state not published and not genesis")
		}
	}

	// 3. root from proof == issuerData.state.сlaimsTreeRoot
	hi, hv, err := coreClaim.HiHv()
	if err != nil {
		return err
	}

	rootFromProof, err := merkletree.RootFromProof(proof.MTP, hi, hv)
	if err != nil {
		return err
	}
	issuerClaimsTreeRoot, err := merkletree.NewHashFromHex(*proof.IssuerData.State.ClaimsTreeRoot)
	if err != nil {
		return fmt.Errorf("invalid state formant: %v", err)
	}

	if rootFromProof.BigInt().Cmp(issuerClaimsTreeRoot.BigInt()) != 0 {
		return errors.New("verifyIden3SparseMerkleTreeProof: root from proof not equal to issuer data claims tree root")
	}

	return nil
}

func bjjSignatureFromHexString(sigHex string) (*babyjub.Signature, error) {
	signatureBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	var sig [64]byte
	copy(sig[:], signatureBytes)
	bjjSig, err := new(babyjub.Signature).Decompress(sig)
	return bjjSig, errors.WithStack(err)
}

func getIden3StateInfo2023FromDIDDocument(document DIDDocument) (*CommonVerificationMethod, error) {
	var iden3StateInfo2023 *CommonVerificationMethod
	for _, a := range document.VerificationMethod {
		if a.Type == "Iden3StateInfo2023" {
			a2 := a
			iden3StateInfo2023 = &a2
			break
		}
	}
	if iden3StateInfo2023 == nil {
		return nil, errors.New("Issuer Iden3StateInfo2023 auth info not found")
	}

	return iden3StateInfo2023, nil
}

// Merklize merklizes verifiable credential
func (vc *W3CCredential) Merklize(ctx context.Context,
	opts ...merklize.MerklizeOption) (*merklize.Merklizer, error) {

	credentialBytes, err := json.Marshal(vc)
	if err != nil {
		return nil, err
	}

	var credentialAsMap map[string]interface{}
	err = json.Unmarshal(credentialBytes, &credentialAsMap)
	if err != nil {
		return nil, err
	}
	delete(credentialAsMap, "proof")

	credentialWithoutProofBytes, err := json.Marshal(credentialAsMap)
	if err != nil {
		return nil, err
	}

	mk, err := merklize.MerklizeJSONLD(ctx,
		bytes.NewReader(credentialWithoutProofBytes), opts...)
	if err != nil {
		return nil, err
	}
	return mk, nil

}

// ErrProofNotFound is an error when specific proof is not found in the credential
var ErrProofNotFound = errors.New("proof not found")

// ErrProofNotSupported is an error when specific proof is not supported for validation
var ErrProofNotSupported = errors.New("proof not supported")

// GetCoreClaimFromProof returns  core claim from given proof
func (vc *W3CCredential) GetCoreClaimFromProof(proofType ProofType) (*core.Claim, error) {
	for _, p := range vc.Proof {
		if p.ProofType() == proofType {
			return p.GetCoreClaim()
		}
	}
	return nil, ErrProofNotFound
}

// ToCoreClaim returns Claim object from W3CCredential
func (vc *W3CCredential) ToCoreClaim(ctx context.Context, opts *CoreClaimOptions) (*core.Claim, error) {
	if opts == nil {
		opts = &CoreClaimOptions{
			RevNonce:              0,
			Version:               0,
			SubjectPosition:       CredentialSubjectPositionIndex,
			MerklizedRootPosition: CredentialMerklizedRootPositionNone,
			Updatable:             false,
			MerklizerOpts:         nil,
		}
	}

	mz, err := vc.Merklize(ctx, opts.MerklizerOpts...)
	if err != nil {
		return nil, err
	}

	credentialType, err := findCredentialType(mz)
	if err != nil {
		return nil, err
	}

	subjectID := vc.CredentialSubject["id"]

	slots, nonMerklized, err := parseSlots(mz, *vc, credentialType)
	if err != nil {
		return nil, err
	}

	// if schema is for non merklized credential, root position must be set to none ('')
	// otherwise default position for merklized position is index.
	if !nonMerklized {
		if opts.MerklizedRootPosition == CredentialMerklizedRootPositionNone {
			opts.MerklizedRootPosition = CredentialMerklizedRootPositionIndex
		}
	} else {
		if opts.MerklizedRootPosition != CredentialMerklizedRootPositionNone {
			return nil, errors.New(
				"merklized root position is not supported for non-merklized claims")
		}
	}

	claim, err := core.NewClaim(
		utils.CreateSchemaHash([]byte(credentialType)),
		core.WithIndexDataBytes(slots.IndexA, slots.IndexB),
		core.WithValueDataBytes(slots.ValueA, slots.ValueB),
		core.WithRevocationNonce(opts.RevNonce),
		core.WithVersion(opts.Version))
	if err != nil {
		return nil, err
	}
	if opts.Updatable {
		claim.SetFlagUpdatable(opts.Updatable)
	}

	if vc.Expiration != nil {
		claim.SetExpirationDate(*vc.Expiration)
	}
	if subjectID != nil {
		var did *w3c.DID
		did, err = w3c.ParseDID(fmt.Sprintf("%v", subjectID))
		if err != nil {
			return nil, err
		}

		var id core.ID
		id, err = core.IDFromDID(*did)
		if err != nil {
			return nil, err
		}

		switch opts.SubjectPosition {
		case "", CredentialSubjectPositionIndex:
			claim.SetIndexID(id)
		case CredentialSubjectPositionValue:
			claim.SetValueID(id)
		default:
			return nil, errors.New("unknown subject position")
		}
	}

	switch opts.MerklizedRootPosition {
	case CredentialMerklizedRootPositionIndex:
		err = claim.SetIndexMerklizedRoot(mz.Root().BigInt())
		if err != nil {
			return nil, err
		}
	case CredentialMerklizedRootPositionValue:
		err = claim.SetValueMerklizedRoot(mz.Root().BigInt())
		if err != nil {
			return nil, err
		}
	case CredentialMerklizedRootPositionNone:
		// Slots where filled earlier. Nothing to do here.
		break
	default:
		return nil, errors.New("unknown merklized root position")
	}

	return claim, nil
}

// CredentialSchema represent the information about credential schema
type CredentialSchema struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

// CredentialStatus represents the URL to fetch claim revocation info directly from the issuer.
type CredentialStatus struct {
	ID              string               `json:"id"`
	Type            CredentialStatusType `json:"type"`
	RevocationNonce uint64               `json:"revocationNonce"`
	StatusIssuer    *CredentialStatus    `json:"statusIssuer,omitempty"`
}

// RHSCredentialStatus contains type, url to fetch RHS info, issuer ID and revocation nonce and backup option to fetch credential status
// Deprecated: use CredentialStatus instead
type RHSCredentialStatus struct {
	ID              string               `json:"id"`
	Type            CredentialStatusType `json:"type"`
	RevocationNonce uint64               `json:"revocationNonce"`
	StatusIssuer    *CredentialStatus    `json:"statusIssuer,omitempty"`
}

// CredentialStatusType type for understanding revocation type
type CredentialStatusType string

// RevocationStatus status of revocation nonce. Info required to check revocation state of claim in circuits
type RevocationStatus struct {
	Issuer TreeState        `json:"issuer"`
	MTP    merkletree.Proof `json:"mtp"`
}

type TreeState struct {
	State              *string `json:"state"`
	RootOfRoots        *string `json:"rootOfRoots,omitempty"`
	ClaimsTreeRoot     *string `json:"claimsTreeRoot,omitempty"`
	RevocationTreeRoot *string `json:"revocationTreeRoot,omitempty"`
}

// WithStatusResolverRegistry return new options
func WithStatusResolverRegistry(registry *CredentialStatusResolverRegistry) W3CProofVerificationOpt {
	return func(opts *w3CProofVerificationConfig) {
		opts.credStatusValidationOpts = append(opts.credStatusValidationOpts,
			WithValidationStatusResolverRegistry(registry))
	}
}

// W3CProofVerificationOpt returns configuration options for W3C proof verification
type W3CProofVerificationOpt func(opts *w3CProofVerificationConfig)

// w3CProofVerificationConfig options for W3C proof verification
type w3CProofVerificationConfig struct {
	credStatusValidationOpts []CredentialStatusValidationOption
	merklizeOptions          []merklize.MerklizeOption
}
