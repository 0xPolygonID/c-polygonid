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

func coreDIDByPath(obj jsonObj, path string) (*core.DID, error) {
	s, err := stringByPath(obj, path)
	if err != nil {
		return nil, err
	}

	return core.ParseDID(s)
}

func coreClaimByPath(obj jsonObj, path string) (*core.Claim, error) {
	s, err := stringByPath(obj, path)
	if err != nil {
		return nil, err
	}
	claimBytes, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	var claim core.Claim
	err = claim.UnmarshalBinary(claimBytes)
	if err != nil {
		return nil, err
	}
	return &claim, nil
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

type errNotFound string

func (e errNotFound) Error() string {
	return fmt.Sprintf("path not found in object: %v", string(e))
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
				return nil, errNotFound(path)
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
	out.TreeState.RootOfRoots = (*merkletree.Hash)(obj.TreeState.RootOfRoots)
	return out, nil
}

func claimWithSigProofFromObj(
	w3cCred verifiable.W3CCredential) (circuits.ClaimWithSigProof, error) {

	var out circuits.ClaimWithSigProof
	var err error

	proof, err := bjjSignatureProof2021(w3cCred)
	if err != nil {
		return out, err
	}

	issuerDID, err := coreDIDByPath(proof, "issuerData.id")
	if err != nil {
		return out, err
	}
	out.IssuerID = &issuerDID.ID
	out.Claim, err = coreClaimByPath(proof, "coreClaim")
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
	out.SignatureProof, err = signatureProofFromObj(proof)
	if err != nil {
		return out, err
	}

	return out, nil
}

func signatureProofFromObj(
	proof jsonObj) (out circuits.BJJSignatureProof, err error) {

	out.Signature, err = sigByPath(proof, "signature")
	if err != nil {
		return out, err
	}
	out.IssuerAuthClaim, err = coreClaimByPath(proof,
		"issuerData.authCoreClaim")
	if err != nil {
		return out, err
	}
	out.IssuerAuthIncProof.TreeState, err = stateFromObjByPaths(proof,
		"issuerData.state.value", "issuerData.state.claimsTreeRoot",
		"issuerData.state.revocationTreeRoot", "issuerData.state.rootOfRoots")
	if err != nil {
		return out, err
	}
	out.IssuerAuthIncProof.Proof, err = proofByPath(proof, "issuerData.mtp")
	if err != nil {
		return out, err
	}

	revocationStatusURL, err := stringByPath(proof,
		"issuerData.credentialStatus.id")
	if err != nil {
		return out, err
	}
	out.IssuerAuthNonRevProof, err = resolveRevocationStatus(
		revocationStatusURL)
	if err != nil {
		return out, err
	}

	return out, nil
}

func stateFromObjByPaths(obj jsonObj,
	statePath, ctrPath, rtrPath, rorPath string) (circuits.TreeState, error) {
	var ts circuits.TreeState
	var err error
	ts.State, err = hashByPath(obj, statePath)
	if err != nil {
		return ts, err
	}
	ts.ClaimsRoot, err = hashByPath(obj, ctrPath)
	if err != nil {
		return ts, err
	}
	ts.RevocationRoot, err = hashByPath(obj, rtrPath)
	if errors.Is(err, errNotFound(rtrPath)) {
		// pass, revocation root is optional
		ts.RevocationRoot = &merkletree.Hash{}
	} else if err != nil {
		return ts, err
	}
	ts.RootOfRoots, err = hashByPath(obj, rorPath)
	if errors.Is(err, errNotFound(rorPath)) {
		// pass, "root of roots" root is optional
		ts.RootOfRoots = &merkletree.Hash{}
	} else if err != nil {
		return ts, err
	}
	return ts, nil
}

func sigByPath(proof jsonObj, s string) (*babyjub.Signature, error) {
	sigBytes, err := bytesFromHexByPath(proof, s)
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

func bytesFromHexByPath(proof jsonObj, s string) ([]byte, error) {
	hexStr, err := stringByPath(proof, s)
	if err != nil {
		return nil, err
	}
	return hex.DecodeString(hexStr)
}

func hashByPath(proof jsonObj, s string) (*merkletree.Hash, error) {
	hashStr, err := stringByPath(proof, s)
	if err != nil {
		return nil, err
	}
	return merkletree.NewHashFromHex(hashStr)
}

func extractProof(
	proof interface{}) (jsonObj, verifiable.ProofType, error) {

	switch p := proof.(type) {
	case jsonObj:
		defaultProofType, ok := p["type"].(string)
		if !ok {
			return nil, "", errors.New("proof type is not specified")
		}
		return p, verifiable.ProofType(defaultProofType), nil
	default:
		return nil, "", errors.New("unexpected proof object")
	}
}

func bjjSignatureProof2021(w3cCred verifiable.W3CCredential) (jsonObj, error) {
	switch p := w3cCred.Proof.(type) {
	case []any:
		for _, proof := range p {
			proofObj, proofType, err := extractProof(proof)
			if err != nil {
				return nil, err
			}
			if proofType == verifiable.BJJSignatureProofType {
				return proofObj, nil
			}
		}
	case any:
		proofObj, proofType, err := extractProof(p)
		if err != nil {
			return nil, err
		}
		if proofType == verifiable.BJJSignatureProofType {
			return proofObj, nil
		}
	}

	return nil, fmt.Errorf("no BJJSignatureProof2021 proof found")
}

func atomicQuerySigV2InputsFromJson(
	in []byte) (circuits.AtomicQuerySigV2Inputs, error) {

	var out circuits.AtomicQuerySigV2Inputs

	var obj2 struct {
		ID                       core.ID         `json:"id"`
		ProfileNonce             jsonInt         `json:"profileNonce"`
		ClaimSubjectProfileNonce jsonInt         `json:"claimSubjectProfileNonce"`
		VerifiableCredentials    json.RawMessage `json:"verifiableCredentials"`
		Request                  jsonObj         `json:"request"`
	}
	err := json.Unmarshal(in, &obj2)
	if err != nil {
		return out, err
	}

	var obj jsonObj
	err = json.Unmarshal(in, &obj)
	if err != nil {
		return out, err
	}

	out.RequestID, err = bigIntByPath(obj2.Request, "id", true)
	if err != nil {
		return out, err
	}
	out.ID = &obj2.ID
	out.ProfileNonce = obj2.ProfileNonce.BigInt()
	out.ClaimSubjectProfileNonce = obj2.ClaimSubjectProfileNonce.BigInt()

	circuitID, err := stringByPath(obj2.Request, "circuitId")
	if err != nil {
		return out, err
	}
	if circuitID != "credentialAtomicQuerySigV2" {
		return out, errors.New("wrong circuit")
	}
	var w3cCred verifiable.W3CCredential
	err = json.Unmarshal(obj2.VerifiableCredentials, &w3cCred)
	if err != nil {
		return out, err
	}

	out.Claim, err = claimWithSigProofFromObj(w3cCred)
	if err != nil {
		return out, err
	}

	out.Query, err = queryFromObj(obj, w3cCred)
	if err != nil {
		return out, err
	}

	out.CurrentTimeStamp = time.Now().Unix()

	return out, nil
}

func queryFromObj(obj jsonObj,
	w3cCred verifiable.W3CCredential) (out circuits.Query, err error) {

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	mz, err := w3cCred.Merklize(ctx)

	var contextURL string
	contextURL, err = stringByPath(obj, "request.query.context")
	if err != nil {
		return out, err
	}
	var contextType string
	contextType, err = stringByPath(obj, "request.query.type")
	if err != nil {
		return out, err
	}
	var httpReq *http.Request
	httpReq, err = http.NewRequestWithContext(ctx, "GET", contextURL,
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
	var contextBytes []byte
	contextBytes, err = io.ReadAll(io.LimitReader(httpResp.Body, 16*1024))
	if err != nil {
		return out, err
	}

	reqObj, err := objByBath(obj, "request.query.req")
	if err != nil {
		return out, err
	}
	if len(reqObj) != 1 {
		return out, errors.New("for now it is supported only one field query")
	}
	for field, op := range reqObj {
		var path merklize.Path
		path, err = merklize.NewFieldPathFromContext(contextBytes,
			contextType, field)
		if err != nil {
			return out, err
		}
		// took from identity-server prepareMerklizedQuery func
		err = path.Prepend("https://www.w3.org/2018/credentials#credentialSubject")
		if err != nil {
			return out, err
		}

		out.ValueProof = new(circuits.ValueProof)
		out.ValueProof.Path, err = path.MtEntry()
		if err != nil {
			return out, err
		}
		var value merklize.Value
		out.ValueProof.MTP, value, err = mz.Proof(ctx, path)
		if err != nil {
			return out, err
		}
		out.ValueProof.Value, err = value.MtEntry()
		if err != nil {
			return out, err
		}

		var opObj jsonObj
		var ok bool
		opObj, ok = op.(jsonObj)
		if !ok {
			return out, errors.New("operation on field is not a json object")
		}
		if len(opObj) != 1 {
			return out, errors.New(
				"for now it is supported only one operation per field")
		}
		for opStr, val := range opObj {
			out.Operator, ok = circuits.QueryOperators[opStr]
			if !ok {
				return out, errors.New("unknown operator")
			}
			switch vt := val.(type) {
			case string:
				i, ok := new(big.Int).SetString(vt, 10)
				if !ok {
					return out, errors.New("invalid big int value")
				}
				out.Values = []*big.Int{i}
			case float64:
				intVal := int64(vt)
				if float64(intVal) != vt {
					return out, errors.New("invalid int value")
				}
				out.Values = []*big.Int{big.NewInt(intVal)}
			default:
				return out, errors.New("value is not a number")
			}
		}
	}
	return out, nil
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

func proofByPath(obj jsonObj, path string) (*merkletree.Proof, error) {
	obj2, err := getByPath(obj, path)
	if err != nil {
		return nil, err
	}
	proofBytes, err := json.Marshal(obj2)
	if err != nil {
		return nil, err
	}
	var p merkletree.Proof
	err = json.Unmarshal(proofBytes, &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}
