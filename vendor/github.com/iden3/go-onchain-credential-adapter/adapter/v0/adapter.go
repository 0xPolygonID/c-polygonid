package adapter

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	contractABI "github.com/iden3/contracts-abi/onchain-non-merklized-issuer-base/v0/go/abi"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/piprate/json-gold/ld"
)

const (
	booleanHashTrue  = "18586133768512220936620570745912940619677854269274689475585506675881198879027"
	booleanHashFalse = "19014214495641488759237505126948346942972912379615652741039992445865937985820"
)

var (
	credentialContexts = [2]string{
		verifiable.JSONLDSchemaW3CCredential2018,
		verifiable.JSONLDSchemaIden3Credential,
	}
)

// Adapter is a bridge between a smart contract and a w3c verifiable credential.
type Adapter struct {
	onchainCli *contractABI.NonMerklizedIssuerBase
	did        *w3c.DID

	id      core.ID
	address string
	chainID uint64

	merklizeOptions merklize.Options
}

// New creates a new adapter.
func New(
	_ context.Context,
	ethcli *ethclient.Client,
	did *w3c.DID,
	merklizeOptions merklize.Options,
) (*Adapter, error) {
	id, err := core.IDFromDID(*did)
	if err != nil {
		return nil, fmt.Errorf("failed to extract issuerID from issuerDID '%s': %w", did, err)
	}
	contractAddressHex, err := core.EthAddressFromID(id)
	if err != nil {
		return nil, fmt.Errorf("failed to extract contract address from issuerID '%s': %w", id, err)
	}
	chainID, err := core.ChainIDfromDID(*did)
	if err != nil {
		return nil, fmt.Errorf("failed to extract chainID from issuerDID '%s': %w", did, err)
	}

	onchainCli, err := contractABI.NewNonMerklizedIssuerBase(contractAddressHex, ethcli)
	if err != nil {
		return nil, fmt.Errorf("failed to create onchain issuer client: %w", err)
	}

	a := &Adapter{
		onchainCli:      onchainCli,
		did:             did,
		id:              id,
		address:         common.BytesToAddress(contractAddressHex[:]).Hex(),
		chainID:         uint64(chainID),
		merklizeOptions: merklizeOptions,
	}

	return a, nil
}

// HexToW3CCredential converts an onchain hex data to a W3C credential.
func (a *Adapter) HexToW3CCredential(
	ctx context.Context,
	hexdata string,
) (*verifiable.W3CCredential, error) {
	credentialData, coreClaimBigInts, credentialSubjectFields, err := a.unpackHexToStructs(hexdata)
	if err != nil {
		return nil,
			fmt.Errorf("failed to unpack hexdata: %w", err)
	}

	coreClaim, err := core.NewClaimFromBigInts(coreClaimBigInts)
	if err != nil {
		return nil,
			fmt.Errorf("failed to create core claim: %w", err)
	}

	var expirationTime *time.Time
	expT, ok := coreClaim.GetExpirationDate()
	if ok {
		e := expT.UTC()
		expirationTime = &e
	}
	issuanceTime := time.Unix(int64(credentialData.IssuanceDate), 0).UTC()

	credentialSubject, err := a.convertCredentialSubject(
		coreClaim,
		credentialData.Context,
		credentialData.Type,
		credentialSubjectFields,
	)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert credential subject: %w", err)
	}

	existenceProof, err := a.existenceProof(ctx, coreClaim)
	if err != nil {
		return nil, err
	}

	displayMethod, err := convertDisplayMethod(credentialData.DisplayMethod)
	if err != nil {
		return nil, fmt.Errorf("failed to convert display method: %w", err)
	}

	return &verifiable.W3CCredential{
		ID:      a.credentialID(credentialData.Id),
		Context: append(credentialContexts[:], credentialData.Context...),
		Type: []string{
			verifiable.TypeW3CVerifiableCredential,
			credentialData.Type,
		},
		CredentialSchema: verifiable.CredentialSchema{
			ID:   credentialData.CredentialSchema.Id,
			Type: credentialData.CredentialSchema.Type,
		},
		Expiration:        expirationTime,
		IssuanceDate:      &issuanceTime,
		Issuer:            a.did.String(),
		CredentialStatus:  a.credentialStatus(coreClaim.GetRevocationNonce()),
		CredentialSubject: credentialSubject,
		Proof:             verifiable.CredentialProofs{existenceProof},
		DisplayMethod:     displayMethod,
	}, nil
}

func (a *Adapter) credentialStatus(revNonce uint64) *verifiable.CredentialStatus {
	id := fmt.Sprintf("%s/credentialStatus?revocationNonce=%d&contractAddress=%d:%s",
		a.did.String(), revNonce, a.chainID, a.address)
	return &verifiable.CredentialStatus{
		ID:              id,
		Type:            verifiable.Iden3OnchainSparseMerkleTreeProof2023,
		RevocationNonce: revNonce,
	}
}

func (a *Adapter) credentialID(id *big.Int) string {
	return fmt.Sprintf("urn:iden3:onchain:%d:%s:%s", a.chainID, a.address, id.String())
}

func (a *Adapter) existenceProof(ctx context.Context, coreClaim *core.Claim) (*verifiable.Iden3SparseMerkleTreeProof, error) {
	hindex, err := coreClaim.HIndex()
	if err != nil {
		return nil,
			fmt.Errorf("failed to get hash index from core claim: %w", err)
	}

	mtpProof, stateInfo, err := a.onchainCli.GetClaimProofWithStateInfo(
		&bind.CallOpts{Context: ctx}, hindex)
	if err != nil {
		return nil,
			fmt.Errorf("failed to get claim proof for hash index '%s': %w", hindex, err)
	}
	if !mtpProof.Existence {
		return nil,
			fmt.Errorf("the hash index '%s' does not exist in the issuer state", hindex)
	}

	latestStateHash, err := merkletree.NewHashFromBigInt(stateInfo.State)
	if err != nil {
		return nil,
			fmt.Errorf("failed to create hash for latest state '%s': %w", stateInfo.State, err)
	}
	latestClaimsOfRootHash, err := merkletree.NewHashFromBigInt(stateInfo.ClaimsRoot)
	if err != nil {
		return nil,
			fmt.Errorf("failed to create hash for latest claims root '%s': %w", stateInfo.ClaimsRoot, err)
	}
	latestRevocationOfRootHash, err := merkletree.NewHashFromBigInt(stateInfo.RevocationsRoot)
	if err != nil {
		return nil,
			fmt.Errorf("failed to create hash for latest revocation root '%s': %w", stateInfo.RevocationsRoot, err)
	}
	latestRootsOfRootHash, err := merkletree.NewHashFromBigInt(stateInfo.RootsRoot)
	if err != nil {
		return nil,
			fmt.Errorf("failed to create hash for latest root of roots root '%s': %w", stateInfo.RootsRoot, err)
	}

	coreClaimHex, err := coreClaim.Hex()
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert core claim to hex: %w", err)
	}

	issuerData := verifiable.IssuerData{
		ID: a.did.String(),
		State: verifiable.State{
			Value:              strPtr(latestStateHash.Hex()),
			ClaimsTreeRoot:     strPtr(latestClaimsOfRootHash.Hex()),
			RevocationTreeRoot: strPtr(latestRevocationOfRootHash.Hex()),
			RootOfRoots:        strPtr(latestRootsOfRootHash.Hex()),
		},
	}

	p, err := convertChainProofToMerkleProof(&mtpProof)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert chain proof to merkle proof: %w", err)
	}

	return &verifiable.Iden3SparseMerkleTreeProof{
		Type:       verifiable.Iden3SparseMerkleTreeProofType,
		CoreClaim:  coreClaimHex,
		IssuerData: issuerData,
		MTP:        p,
	}, nil
}

func (a *Adapter) unpackHexToStructs(credentialHex string) (
	out0 contractABI.INonMerklizedIssuerCredentialData,
	out1 [8]*big.Int,
	out2 []contractABI.INonMerklizedIssuerSubjectField,
	err error,
) {
	credentialHex = strings.TrimPrefix(credentialHex, "0x")
	credentialHex = strings.TrimPrefix(credentialHex, "0X")
	hexBytes, err := hex.DecodeString(credentialHex)
	if err != nil {
		return out0, out1, out2, fmt.Errorf("failed to decode hex '%s': %w", credentialHex, err)
	}
	onchainABI, err := contractABI.NonMerklizedIssuerBaseMetaData.GetAbi()
	if err != nil {
		return out0, out1, out2, fmt.Errorf("failed to get ABI: %w", err)
	}
	out, err := onchainABI.Unpack("getCredential", hexBytes)
	if err != nil {
		return out0, out1, out2, fmt.Errorf("failed to unpack hex '%s': %w", credentialHex, err)
	}

	out0 = *abi.ConvertType(out[0], new(contractABI.INonMerklizedIssuerCredentialData)).(*contractABI.INonMerklizedIssuerCredentialData)
	out1 = *abi.ConvertType(out[1], new([8]*big.Int)).(*[8]*big.Int)
	out2 = *abi.ConvertType(out[2], new([]contractABI.INonMerklizedIssuerSubjectField)).(*[]contractABI.INonMerklizedIssuerSubjectField)
	return out0, out1, out2, nil
}

func strPtr(s string) *string {
	return &s
}

func convertChainProofToMerkleProof(proof *contractABI.SmtLibProof) (*merkletree.Proof, error) {
	var (
		existence bool
		nodeAux   *merkletree.NodeAux
		err       error
	)

	if proof.Existence {
		existence = true
	} else {
		existence = false
		if proof.AuxExistence {
			nodeAux = &merkletree.NodeAux{}
			nodeAux.Key, err = merkletree.NewHashFromBigInt(proof.AuxIndex)
			if err != nil {
				return nil,
					fmt.Errorf("failed to create hash for AuxIndex '%s': %w", proof.AuxIndex, err)
			}
			nodeAux.Value, err = merkletree.NewHashFromBigInt(proof.AuxValue)
			if err != nil {
				return nil,
					fmt.Errorf("failed to create hash for AuxValue '%s': %w", proof.AuxValue, err)
			}
		}
	}

	allSiblings := make([]*merkletree.Hash, len(proof.Siblings))
	for i, s := range proof.Siblings {
		var sh *merkletree.Hash
		sh, err = merkletree.NewHashFromBigInt(s)
		if err != nil {
			return nil,
				fmt.Errorf("failed to create hash for sibling '%s': %w", s, err)
		}
		allSiblings[i] = sh
	}

	p, err := merkletree.NewProofFromData(existence, allSiblings, nodeAux)
	if err != nil {
		return nil,
			fmt.Errorf("failed to create merkle proof: %w", err)
	}

	return p, nil
}

func (a *Adapter) convertCredentialSubject(
	coreClaim *core.Claim,
	contractContexts []string,
	credentialType string,
	credentialSubjectFields []contractABI.INonMerklizedIssuerSubjectField,
) (map[string]any, error) {
	contextbytes, err := json.Marshal(map[string][]string{
		"@context": append(credentialContexts[:], contractContexts...),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal context: %w", err)
	}

	credentialSubject := make(map[string]any)
	for _, f := range credentialSubjectFields {
		datatype, err := a.merklizeOptions.TypeFromContext(
			contextbytes,
			fmt.Sprintf("%s.%s", credentialType, f.Key),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to extract type for field '%s': %w", f.Key, err)
		}

		switch datatype {
		case ld.XSDBoolean:
			switch f.Value.String() {
			case booleanHashTrue:
				credentialSubject[f.Key] = true
			case booleanHashFalse:
				credentialSubject[f.Key] = false
			default:
				return nil, fmt.Errorf("unsupported boolean value '%s'", f.Value)
			}
		case ld.XSDNS + "positiveInteger",
			ld.XSDNS + "nonNegativeInteger",
			ld.XSDNS + "negativeInteger",
			ld.XSDNS + "nonPositiveInteger":
			credentialSubject[f.Key] = f.Value.String()
		case ld.XSDInteger:
			credentialSubject[f.Key] = f.Value.Int64()
		case ld.XSDString:
			source := string(f.RawValue)
			if err := validateSourceValue(datatype, f.Value, source); err != nil {
				return nil, fmt.Errorf("field '%s': %w", f.Key, err)
			}
			credentialSubject[f.Key] = source
		case ld.XSDNS + "dateTime":
			timestamp := big.NewInt(0).SetBytes(f.RawValue)
			sourceTime := time.Unix(
				timestamp.Int64(),
				0,
			).UTC().Format(time.RFC3339Nano)
			if err := validateSourceValue(datatype, f.Value, sourceTime); err != nil {
				return nil, fmt.Errorf("filed '%s': %w", f.Key, err)
			}
			credentialSubject[f.Key] = sourceTime
		case ld.XSDDouble:
			v, _, err := big.NewFloat(0).Parse(
				hex.EncodeToString(f.RawValue), 16)
			if err != nil {
				return nil,
					fmt.Errorf("failed to convert string '%s' to float for field '%s'", f.RawValue, f.Key)
			}
			sourceDouble, _ := v.Float64()
			if err := validateSourceValue(datatype, f.Value, sourceDouble); err != nil {
				return nil, fmt.Errorf("field '%s': %w", f.Key, err)
			}
			credentialSubject[f.Key] = sourceDouble
		default:
			return nil, fmt.Errorf("unsupported type for key '%s': %s", f.Key, datatype)
		}
	}
	credentialSubject["type"] = credentialType

	subjectID, err := coreClaim.GetID()
	if errors.Is(err, core.ErrNoID) { // self claim
		return credentialSubject, nil
	} else if err != nil {
		return nil, fmt.Errorf("failed to get ID from core claim: %w", err)
	}

	subjectDID, err := core.ParseDIDFromID(subjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to convert subjectID to DID: %w", err)
	}
	credentialSubject["id"] = subjectDID.String()

	return credentialSubject, nil
}

func validateSourceValue(datatype string, originHash *big.Int, source any) error {
	sourceHash, err := merklize.HashValue(datatype, source)
	if err != nil {
		return fmt.Errorf("failed hash value '%s' with data type '%s': %w", source, datatype, err)
	}
	if sourceHash == nil {
		return fmt.Errorf("source value not provided for type '%s'", datatype)
	}
	if sourceHash.Cmp(originHash) != 0 {
		return fmt.Errorf("source value '%s' does not match origin value '%s'", sourceHash, originHash)
	}
	return nil
}

func convertDisplayMethod(
	onchainDisplayMethod contractABI.INonMerklizedIssuerDisplayMethod,
) (*verifiable.DisplayMethod, error) {
	if onchainDisplayMethod.Id == "" && onchainDisplayMethod.Type == "" {
		return nil, nil
	}

	// nolint: gocritic // the switch for changes in the future
	switch onchainDisplayMethod.Type {
	case string(verifiable.Iden3BasicDisplayMethodV1):
		return &verifiable.DisplayMethod{
			ID:   onchainDisplayMethod.Id,
			Type: verifiable.Iden3BasicDisplayMethodV1,
		}, nil
	}

	return nil, fmt.Errorf("unsupported display method type '%s'", onchainDisplayMethod.Type)
}
