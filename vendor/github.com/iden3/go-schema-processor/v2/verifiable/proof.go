package verifiable

import (
	"encoding/hex"
	"encoding/json"
	"errors"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/babyjub"
	mt "github.com/iden3/go-merkletree-sql/v2"
)

// ProofType represent proofs types.
type ProofType string

// IssuerData is the data that is used to create a proof
type IssuerData struct {
	ID               string      `json:"id,omitempty"`
	State            State       `json:"state,omitempty"`
	AuthCoreClaim    string      `json:"authCoreClaim,omitempty"`
	MTP              *mt.Proof   `json:"mtp,omitempty"`
	CredentialStatus interface{} `json:"credentialStatus,omitempty"`
}

func (id *IssuerData) authClaim() (*core.Claim, error) {
	var claim core.Claim
	err := claim.FromHex(id.AuthCoreClaim)
	return &claim, err
}

// State represents the state of the issuer
type State struct {
	TxID               *string `json:"txId,omitempty"`
	BlockTimestamp     *int    `json:"blockTimestamp,omitempty"`
	BlockNumber        *int    `json:"blockNumber,omitempty"`
	RootOfRoots        *string `json:"rootOfRoots,omitempty"`
	ClaimsTreeRoot     *string `json:"claimsTreeRoot,omitempty"`
	RevocationTreeRoot *string `json:"revocationTreeRoot,omitempty"`
	Value              *string `json:"value,omitempty"`
	Status             string  `json:"status,omitempty"`
}

// BJJSignatureProof2021 JSON-LD BBJJSignatureProof
type BJJSignatureProof2021 struct {
	Type       ProofType  `json:"type"`
	IssuerData IssuerData `json:"issuerData"`
	CoreClaim  string     `json:"coreClaim"`
	Signature  string     `json:"signature"`
}

func (p *BJJSignatureProof2021) UnmarshalJSON(in []byte) error {
	var obj struct {
		Type       ProofType       `json:"type"`
		IssuerData json.RawMessage `json:"issuerData"`
		CoreClaim  string          `json:"coreClaim"`
		Signature  string          `json:"signature"`
	}
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return err
	}
	if obj.Type != BJJSignatureProofType {
		return errors.New("invalid proof type")
	}
	p.Type = obj.Type
	err = json.Unmarshal(obj.IssuerData, &p.IssuerData)
	if err != nil {
		return err
	}
	if err := validateHexCoreClaim(obj.CoreClaim); err != nil {
		return err
	}
	p.CoreClaim = obj.CoreClaim
	if err := validateCompSignature(obj.Signature); err != nil {
		return err
	}
	p.Signature = obj.Signature
	return nil
}

func validateHexCoreClaim(in string) error {
	var claim core.Claim
	err := claim.FromHex(in)
	return err
}

func validateCompSignature(in string) error {
	sigBytes, err := hex.DecodeString(in)
	if err != nil {
		return err
	}
	var sig babyjub.SignatureComp
	if len(sigBytes) != len(sig) {
		return errors.New("invalid signature length")
	}
	copy(sig[:], sigBytes)
	_, err = sig.Decompress()
	return err
}

func (p *BJJSignatureProof2021) ProofType() ProofType {
	return p.Type
}

func (p *BJJSignatureProof2021) GetCoreClaim() (*core.Claim, error) {
	var coreClaim core.Claim
	err := coreClaim.FromHex(p.CoreClaim)
	return &coreClaim, err
}

// Iden3SparseMerkleProof JSON-LD structure
//
// Deprecated: replaced with Iden3SparseMerkleTreeProof
type Iden3SparseMerkleProof struct {
	Type ProofType `json:"type"`

	IssuerData IssuerData `json:"issuerData"`
	CoreClaim  string     `json:"coreClaim"`

	MTP *mt.Proof `json:"mtp"`
}

func (p *Iden3SparseMerkleProof) UnmarshalJSON(in []byte) error {
	var obj struct {
		Type       ProofType       `json:"type"`
		IssuerData json.RawMessage `json:"issuerData"`
		CoreClaim  string          `json:"coreClaim"`
		MTP        *mt.Proof       `json:"mtp"`
	}
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return err
	}
	if obj.Type != Iden3SparseMerkleProofType {
		return errors.New("invalid proof type")
	}
	p.Type = obj.Type
	err = json.Unmarshal(obj.IssuerData, &p.IssuerData)
	if err != nil {
		return err
	}
	if err := validateHexCoreClaim(obj.CoreClaim); err != nil {
		return err
	}
	p.CoreClaim = obj.CoreClaim
	p.MTP = obj.MTP
	return nil
}

func (p *Iden3SparseMerkleProof) ProofType() ProofType {
	return p.Type
}

func (p *Iden3SparseMerkleProof) GetCoreClaim() (*core.Claim, error) {
	var coreClaim core.Claim
	err := coreClaim.FromHex(p.CoreClaim)
	return &coreClaim, err
}

// Iden3SparseMerkleTreeProof JSON-LD structure
type Iden3SparseMerkleTreeProof struct {
	Type ProofType `json:"type"`

	IssuerData IssuerData `json:"issuerData"`
	CoreClaim  string     `json:"coreClaim"`

	MTP *mt.Proof `json:"mtp"`
}

func (p *Iden3SparseMerkleTreeProof) UnmarshalJSON(in []byte) error {
	var obj struct {
		Type       ProofType       `json:"type"`
		IssuerData json.RawMessage `json:"issuerData"`
		CoreClaim  string          `json:"coreClaim"`
		MTP        *mt.Proof       `json:"mtp"`
	}
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return err
	}
	if obj.Type != Iden3SparseMerkleTreeProofType {
		return errors.New("invalid proof type")
	}
	p.Type = obj.Type
	err = json.Unmarshal(obj.IssuerData, &p.IssuerData)
	if err != nil {
		return err
	}
	if err := validateHexCoreClaim(obj.CoreClaim); err != nil {
		return err
	}
	p.CoreClaim = obj.CoreClaim
	p.MTP = obj.MTP
	return nil
}

func (p *Iden3SparseMerkleTreeProof) ProofType() ProofType {
	return p.Type
}

func (p *Iden3SparseMerkleTreeProof) GetCoreClaim() (*core.Claim, error) {
	var coreClaim core.Claim
	err := coreClaim.FromHex(p.CoreClaim)
	return &coreClaim, err
}

// ProofPurpose is alias for string, represents proof purpose
type ProofPurpose string

// ProofData is structure that represents SnarkJS library result of proof generation
type ProofData struct {
	A        []string   `json:"pi_a"`
	B        [][]string `json:"pi_b"`
	C        []string   `json:"pi_c"`
	Protocol string     `json:"protocol"`
}

// ZKProof is proof data with public signals
type ZKProof struct {
	Proof      *ProofData `json:"proof"`
	PubSignals []string   `json:"pub_signals"`
}

type CommonProof jsonObj

func (p *CommonProof) ProofType() ProofType {
	ptStr, err := jsonObjGetString(*p, "type")
	if err != nil {
		return ""
	}
	return ProofType(ptStr)
}

func (p *CommonProof) GetCoreClaim() (*core.Claim, error) {
	claimHex, err := jsonObjGetString(*p, "coreClaim")
	if err != nil {
		return nil, err
	}
	var claim core.Claim
	err = claim.FromHex(claimHex)
	return &claim, err
}

func (p *CommonProof) UnmarshalJSON(bytes []byte) error {
	var obj jsonObj
	err := json.Unmarshal(bytes, &obj)
	if err != nil {
		return err
	}
	_, err = jsonObjGetString(obj, "type")
	if err != nil {
		return err
	}
	*p = obj
	return nil
}

type CredentialProof interface {
	ProofType() ProofType
	GetCoreClaim() (*core.Claim, error)
}

type CredentialProofs []CredentialProof

func reUnmarshalFromObj(obj jsonObj, v interface{}) error {
	objBytes, err := json.Marshal(obj)
	if err != nil {
		return err
	}

	return json.Unmarshal(objBytes, v)
}

func extractProof(proof any) (CredentialProof, error) {
	proofJ, ok := proof.(jsonObj)
	if !ok {
		return nil, errors.New("proof is not an object")
	}
	proofType, ok := proofJ["type"].(string)
	if !ok {
		return nil, errors.New("proof type is not specified")
	}

	switch ProofType(proofType) {
	case BJJSignatureProofType:
		var proof BJJSignatureProof2021
		err := reUnmarshalFromObj(proofJ, &proof)
		return &proof, err
	case Iden3SparseMerkleProofType:
		var proof Iden3SparseMerkleProof
		err := reUnmarshalFromObj(proofJ, &proof)
		return &proof, err
	case Iden3SparseMerkleTreeProofType:
		var proof Iden3SparseMerkleTreeProof
		err := reUnmarshalFromObj(proofJ, &proof)
		return &proof, err
	default:
		var proof CommonProof
		err := reUnmarshalFromObj(proofJ, &proof)
		return &proof, err
	}
}

func (cps *CredentialProofs) UnmarshalJSON(bs []byte) error {
	var i interface{}
	err := json.Unmarshal(bs, &i)
	if err != nil {
		return err
	}
	switch p := i.(type) {
	case []interface{}:
		for _, proofI := range p {
			proof, err := extractProof(proofI)
			if err != nil {
				return err
			}
			*cps = append(*cps, proof)
		}
	case interface{}:
		proof, err := extractProof(p)
		if err != nil {
			return err
		}
		*cps = append(*cps, proof)
	default:
		return errors.New("proof is not an array or an object")
	}
	return nil
}
