package c_polygonid

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/merklize"
	"github.com/iden3/go-schema-processor/verifiable"
)

type jsonObj = map[string]any

var httpClient = &http.Client{}

func stringByPath(obj jsonObj, path string) (string, error) {
	v, err := getByPath(obj, path)
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("not a string at path: %v", path)
	}
	return s, nil
}

// if allowNumbers is true, then the value can also be a number, not only strings
func bigIntByPath(obj jsonObj, path string,
	allowNumbers bool) (*big.Int, error) {

	v, err := getByPath(obj, path)
	if err != nil {
		return nil, err
	}

	switch vt := v.(type) {
	case string:
		i, ok := new(big.Int).SetString(vt, 10)
		if !ok {
			return nil, errors.New("not a big int")
		}
		return i, nil
	case float64:
		if !allowNumbers {
			return nil, errors.New("not a string")
		}
		ii := int64(vt)
		if float64(ii) != vt {
			return nil, errors.New("not an int")
		}
		return big.NewInt(0).SetInt64(ii), nil
	default:
		return nil, errors.New("not a string")
	}
}

func objByBath(proof jsonObj, s string) (jsonObj, error) {
	v, err := getByPath(proof, s)
	if err != nil {
		return nil, err
	}
	obj, ok := v.(jsonObj)
	if !ok {
		return nil, errors.New("not an object")
	}
	return obj, nil
}

func getByPath(obj jsonObj, path string) (any, error) {
	parts := strings.Split(path, ".")

	var curObj = obj
	for i, part := range parts {
		if part == "" {
			return nil, errors.New("path is empty")
		}
		if i == len(parts)-1 {
			v, ok := curObj[part]
			if !ok {
				return nil,
					fmt.Errorf("path not found in object: %v", path)
			}
			return v, nil
		}

		nextObj, ok := curObj[part]
		if !ok {
			return nil, fmt.Errorf("path not found: %v", path)
		}
		curObj, ok = nextObj.(jsonObj)
		if !ok {
			return nil, errors.New("not a json object")
		}
	}

	return nil, errors.New("should not happen")
}

func resolveRevocationStatus(url string) (out circuits.MTProof, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url,
		http.NoBody)
	if err != nil {
		return out, err
	}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return out, err
	}
	defer func() {
		err2 := httpResp.Body.Close()
		if err == nil {
			err = err2
		}
	}()
	if httpResp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("unexpected status code: %v",
			httpResp.StatusCode)
	}
	respData, err := io.ReadAll(io.LimitReader(httpResp.Body, 16*1024))
	if err != nil {
		return out, err
	}
	var obj struct {
		TreeState struct {
			State          *hexHash `json:"state"`              // identity state
			ClaimsRoot     *hexHash `json:"claimsTreeRoot"`     // claims tree root
			RevocationRoot *hexHash `json:"revocationTreeRoot"` // revocation tree root
			RootOfRoots    *hexHash `json:"rootOfRoots"`        // root of roots tree root

		} `json:"issuer"`
		Proof *merkletree.Proof `json:"mtp"`
	}
	err = json.Unmarshal(respData, &obj)
	if err != nil {
		return out, err
	}
	out.Proof = obj.Proof
	out.TreeState.State = (*merkletree.Hash)(obj.TreeState.State)
	out.TreeState.ClaimsRoot = (*merkletree.Hash)(obj.TreeState.ClaimsRoot)
	out.TreeState.RevocationRoot = (*merkletree.Hash)(obj.TreeState.RevocationRoot)
	if out.TreeState.RevocationRoot == nil {
		out.TreeState.RevocationRoot = &merkletree.Hash{}
	}
	out.TreeState.RootOfRoots = (*merkletree.Hash)(obj.TreeState.RootOfRoots)
	if out.TreeState.RootOfRoots == nil {
		out.TreeState.RootOfRoots = &merkletree.Hash{}
	}
	return out, nil
}

func claimWithSigProofFromObj(
	w3cCred verifiable.W3CCredential) (circuits.ClaimWithSigProof, error) {

	var out circuits.ClaimWithSigProof

	proofI := findProofByType(w3cCred, verifiable.BJJSignatureProofType)
	if proofI == nil {
		return out, fmt.Errorf("no %v proofs found",
			verifiable.BJJSignatureProofType)
	}

	var err error
	proof, ok := proofI.(*verifiable.BJJSignatureProof2021)
	if !ok {
		return out, errors.New("proof is not of type BJJSignatureProof2021")
	}
	issuerDID, err := core.ParseDID(proof.IssuerData.ID)
	if err != nil {
		return out, err
	}

	out.IssuerID = &issuerDID.ID
	out.Claim, err = proof.GetCoreClaim()
	if err != nil {
		return out, err
	}

	credStatus, ok := w3cCred.CredentialStatus.(jsonObj)
	if !ok {
		return out, errors.New("not a json object")
	}
	revocationStatusURL, err := stringByPath(credStatus, "id")
	if err != nil {
		return out, err
	}
	out.NonRevProof, err = resolveRevocationStatus(revocationStatusURL)
	if err != nil {
		return out, err
	}
	out.SignatureProof, err = signatureProof(*proof)
	if err != nil {
		return out, err
	}

	return out, nil
}

func sigFromHex(sigHex string) (*babyjub.Signature, error) {
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return nil, err
	}
	var compSig babyjub.SignatureComp
	if len(sigBytes) != len(compSig) {
		return nil, fmt.Errorf("signature length is not %v", len(compSig))
	}
	copy(compSig[:], sigBytes)
	return compSig.Decompress()
}

func signatureProof(proof verifiable.BJJSignatureProof2021,
) (out circuits.BJJSignatureProof, err error) {

	out.Signature, err = sigFromHex(proof.Signature)
	if err != nil {
		return out, err
	}
	out.IssuerAuthClaim = new(core.Claim)
	err = out.IssuerAuthClaim.FromHex(proof.IssuerData.AuthCoreClaim)
	if err != nil {
		return
	}
	out.IssuerAuthIncProof.TreeState, err = treeState(proof.IssuerData.State)
	if err != nil {
		return out, err
	}
	out.IssuerAuthIncProof.Proof = proof.IssuerData.MTP
	credStatus, ok := proof.IssuerData.CredentialStatus.(jsonObj)
	if !ok {
		return out, errors.New("credential status is not of object type")
	}
	revocationStatusURL, err := stringByPath(credStatus, "id")
	if err != nil {
		return out, err
	}
	out.IssuerAuthNonRevProof, err =
		resolveRevocationStatus(revocationStatusURL)
	if err != nil {
		return out, err
	}

	return out, nil
}

func findProofByType(w3cCred verifiable.W3CCredential,
	proofType verifiable.ProofType) verifiable.CredentialProof {

	for _, p := range w3cCred.Proof {
		if p.ProofType() == proofType {
			return p
		}
	}

	return nil
}

type inputsRequest struct {
	ID                       core.ID         `json:"id"`
	ProfileNonce             JsonBigInt      `json:"profileNonce"`
	ClaimSubjectProfileNonce JsonBigInt      `json:"claimSubjectProfileNonce"`
	VerifiableCredentials    json.RawMessage `json:"verifiableCredentials"`
	Request                  jsonObj         `json:"request"`
}

type AtomicQueryInputsResponse struct {
	Inputs                 circuits.InputsMarshaller
	VerifiablePresentation map[string]any
}

func AtomicQueryMtpV2InputsFromJson(ctx context.Context,
	in []byte) (AtomicQueryInputsResponse, error) {

	var out AtomicQueryInputsResponse
	var inpMarsh circuits.AtomicQueryMTPV2Inputs

	var obj inputsRequest
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return out, err
	}

	inpMarsh.RequestID, err = bigIntByPath(obj.Request, "id", true)
	if err != nil {
		return out, err
	}
	inpMarsh.ID = &obj.ID
	inpMarsh.ProfileNonce = obj.ProfileNonce.BigInt()
	inpMarsh.ClaimSubjectProfileNonce = obj.ClaimSubjectProfileNonce.BigInt()

	circuitID, err := stringByPath(obj.Request, "circuitId")
	if err != nil {
		return out, err
	}
	if circuitID != string(circuits.AtomicQueryMTPV2CircuitID) {
		return out, errors.New("wrong circuit")
	}
	var w3cCred verifiable.W3CCredential
	err = json.Unmarshal(obj.VerifiableCredentials, &w3cCred)
	if err != nil {
		return out, err
	}

	inpMarsh.Claim, err = claimWithMtpProofFromObj(w3cCred)
	if err != nil {
		return out, err
	}

	inpMarsh.Query, out.VerifiablePresentation, err =
		queryFromObj(ctx, w3cCred, obj.Request)
	if err != nil {
		return out, err
	}

	inpMarsh.CurrentTimeStamp = time.Now().Unix()

	out.Inputs = inpMarsh

	return out, nil
}

func fmtVerifiablePresentation(context string, tp string, field string,
	value any) map[string]any {

	var ldContext any

	const baseContext = "https://www.w3.org/2018/credentials/v1"
	if context == baseContext {
		ldContext = baseContext
	} else {
		ldContext = []string{baseContext, context}
	}

	return map[string]any{
		"@context": ldContext,
		"@type":    "VerifiablePresentation",
		"verifiableCredential": map[string]any{
			"@type": tp,
			field:   value,
		},
	}
}

func AtomicQuerySigV2InputsFromJson(ctx context.Context,
	in []byte) (AtomicQueryInputsResponse, error) {

	var out AtomicQueryInputsResponse
	var inpMarsh circuits.AtomicQuerySigV2Inputs

	var obj inputsRequest
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return out, err
	}

	inpMarsh.RequestID, err = bigIntByPath(obj.Request, "id", true)
	if err != nil {
		return out, err
	}
	inpMarsh.ID = &obj.ID
	inpMarsh.ProfileNonce = obj.ProfileNonce.BigInt()
	inpMarsh.ClaimSubjectProfileNonce = obj.ClaimSubjectProfileNonce.BigInt()

	circuitID, err := stringByPath(obj.Request, "circuitId")
	if err != nil {
		return out, err
	}
	if circuitID != string(circuits.AtomicQuerySigV2CircuitID) {
		return out, errors.New("wrong circuit")
	}
	var w3cCred verifiable.W3CCredential
	err = json.Unmarshal(obj.VerifiableCredentials, &w3cCred)
	if err != nil {
		return out, err
	}

	inpMarsh.Claim, err = claimWithSigProofFromObj(w3cCred)
	if err != nil {
		return out, err
	}

	inpMarsh.Query, out.VerifiablePresentation, err =
		queryFromObj(ctx, w3cCred, obj.Request)
	if err != nil {
		return out, err
	}

	inpMarsh.CurrentTimeStamp = time.Now().Unix()

	out.Inputs = inpMarsh

	return out, nil
}

func buildQueryPath(ctx context.Context, contextURL string, contextType string,
	field string) (path merklize.Path, err error) {

	var httpReq *http.Request
	httpReq, err = http.NewRequestWithContext(ctx, http.MethodGet, contextURL,
		http.NoBody)
	if err != nil {
		return merklize.Path{}, err
	}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return merklize.Path{}, err
	}
	defer func() {
		err2 := httpResp.Body.Close()
		if err == nil {
			err = err2
		}
	}()

	var contextBytes []byte
	contextBytes, err = io.ReadAll(io.LimitReader(httpResp.Body, 16*1024))
	if err != nil {
		return
	}

	path, err = merklize.NewFieldPathFromContext(contextBytes, contextType,
		field)
	if err != nil {
		return
	}
	// took from identity-server prepareMerklizedQuery func
	err = path.Prepend("https://www.w3.org/2018/credentials#credentialSubject")
	if err != nil {
		return
	}

	return
}

func queryFromObj(ctx context.Context, w3cCred verifiable.W3CCredential,
	requestObj jsonObj) (out circuits.Query, verifiablePresentation jsonObj,
	err error) {

	mz, err := w3cCred.Merklize(ctx)
	if err != nil {
		return out, nil, err
	}

	var contextURL string
	contextURL, err = stringByPath(requestObj, "query.context")
	if err != nil {
		return out, nil, err
	}
	var contextType string
	contextType, err = stringByPath(requestObj, "query.type")
	if err != nil {
		return out, nil, err
	}
	credSubjObj, err := objByBath(requestObj, "query.credentialSubject")
	if err != nil {
		return out, nil, err
	}
	field, op, err := extractSingleEntry(credSubjObj)
	if err != nil {
		return out, nil,
			fmt.Errorf("unable to extract field from query: %w", err)
	}
	path, err := buildQueryPath(ctx, contextURL, contextType, field)
	if err != nil {
		return out, nil, err
	}

	out.ValueProof = new(circuits.ValueProof)
	out.ValueProof.Path, err = path.MtEntry()
	if err != nil {
		return out, nil, err
	}
	var value merklize.Value
	out.ValueProof.MTP, value, err = mz.Proof(ctx, path)
	if err != nil {
		return out, nil, err
	}
	out.ValueProof.Value, err = value.MtEntry()
	if err != nil {
		return out, nil, err
	}

	var opObj jsonObj
	var ok bool
	opObj, ok = op.(jsonObj)
	if !ok {
		return out, nil, errors.New("operation on field is not a json object")
	}
	opStr, val, err := extractSingleEntry(opObj)
	switch err {
	case errMultipleEntries:
		return out, nil, errors.New("only one operation per field is supported")
	case errNoEntry:
		// handle selective disclosure
		out.Operator = circuits.EQ
		out.Values = []*big.Int{out.ValueProof.Value}
		rawValue, err := mz.RawValue(path)
		if err != nil {
			return out, nil, err
		}
		verifiablePresentation = fmtVerifiablePresentation(contextURL,
			contextType, field, rawValue)
	default:
		out.Operator, ok = circuits.QueryOperators[opStr]
		if !ok {
			return out, nil, errors.New("unknown operator")
		}
		switch vt := val.(type) {
		case string:
			i, ok := new(big.Int).SetString(vt, 10)
			if !ok {
				return out, nil, errors.New("invalid big int value")
			}
			out.Values = []*big.Int{i}
		case float64:
			intVal := int64(vt)
			if float64(intVal) != vt {
				return out, nil, errors.New("invalid int value")
			}
			out.Values = []*big.Int{big.NewInt(intVal)}
		default:
			return out, nil, errors.New("value is not a number")
		}
	}
	return out, verifiablePresentation, nil
}

var errNoEntry = errors.New("no entry")
var errMultipleEntries = errors.New("multiple entries")

func extractSingleEntry(obj jsonObj) (key string, val any, err error) {
	if len(obj) > 1 {
		return key, val, errMultipleEntries
	}
	for key, val = range obj {
		return key, val, nil
	}
	return key, val, errNoEntry
}

type hexHash merkletree.Hash

func (h *hexHash) UnmarshalJSON(i []byte) error {
	var str string
	err := json.Unmarshal(i, &str)
	if err != nil {
		return err
	}
	hashBytes, err := hex.DecodeString(str)
	if err != nil {
		return err
	}
	if len(hashBytes) != len(*h) {
		return errors.New("invalid hash length")
	}

	copy(h[:], hashBytes)
	h2 := (*merkletree.Hash)(h)
	bi := h2.BigInt()
	if !utils.CheckBigIntInField(bi) {
		return errors.New("hash is not in the field")
	}
	return nil
}

func claimWithMtpProofFromObj(
	w3cCred verifiable.W3CCredential) (circuits.ClaimWithMTPProof, error) {

	var out circuits.ClaimWithMTPProof

	proofI := findProofByType(w3cCred, verifiable.Iden3SparseMerkleProofType)
	if proofI == nil {
		return out, fmt.Errorf("no %v proofs found",
			verifiable.Iden3SparseMerkleProofType)
	}

	var err error
	proof, ok := proofI.(*verifiable.Iden3SparseMerkleProof)
	if !ok {
		return out, errors.New("proof is not a sparse merkle proof")
	}
	issuerDID, err := core.ParseDID(proof.IssuerData.ID)
	if err != nil {
		return out, err
	}

	out.IssuerID = &issuerDID.ID
	out.Claim, err = proof.GetCoreClaim()
	if err != nil {
		return out, err
	}

	credStatus, ok := w3cCred.CredentialStatus.(jsonObj)
	if !ok {
		return out, errors.New("not a json object")
	}
	revocationStatusURL, err := stringByPath(credStatus, "id")
	if err != nil {
		return out, err
	}
	out.NonRevProof, err = resolveRevocationStatus(revocationStatusURL)
	if err != nil {
		return out, err
	}
	out.IncProof.Proof = proof.MTP
	out.IncProof.TreeState, err = treeState(proof.IssuerData.State)
	if err != nil {
		return out, err
	}

	return out, nil
}

func treeState(state verifiable.State) (ts circuits.TreeState, err error) {
	if state.Value == nil {
		return ts, errors.New("state value is nil")
	}
	ts.State, err = merkletree.NewHashFromHex(*state.Value)
	if err != nil {
		return ts, err
	}
	if state.ClaimsTreeRoot == nil {
		return ts, errors.New("state claims tree root is nil")
	}
	ts.ClaimsRoot, err = merkletree.NewHashFromHex(*state.ClaimsTreeRoot)
	if err != nil {
		return ts, err
	}
	if state.RevocationTreeRoot != nil {
		ts.RevocationRoot, err =
			merkletree.NewHashFromHex(*state.RevocationTreeRoot)
		if err != nil {
			return ts, err
		}
	} else {
		ts.RevocationRoot = &merkletree.Hash{}
	}
	if state.RootOfRoots != nil {
		ts.RootOfRoots, err = merkletree.NewHashFromHex(*state.RootOfRoots)
		if err != nil {
			return ts, err
		}
	} else {
		ts.RootOfRoots = &merkletree.Hash{}
	}
	return
}
