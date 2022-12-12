package c_polygonid

import (
	"bytes"
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

func coreIDByPath(obj jsonObj, path string) (*core.ID, error) {
	s, err := stringByPath(obj, path)
	if err != nil {
		return nil, err
	}

	coreID, err := core.IDFromString(s)
	if err != nil {
		return nil, err
	}

	return &coreID, nil
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
	httpResp, err := http.DefaultClient.Do(httpReq)
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

func claimWithSigProofFromObj(obj jsonObj) (circuits.ClaimWithSigProof, error) {
	var out circuits.ClaimWithSigProof
	var err error

	proof, err := findProofByType(obj, "BJJSignature2021")
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
	revocationStatusURL, err := stringByPath(obj,
		"verifiableCredentials.credentialStatus.id")
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
	// TODO: check last two paths with Vlad
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

func findProofByType(obj jsonObj, proofType string) (jsonObj, error) {
	o, err := getByPath(obj, "verifiableCredentials.proof")
	if err != nil {
		return nil, err
	}

	switch v := o.(type) {
	case []any:
		for _, proof := range v {
			proofObj, ok := proof.(jsonObj)
			if !ok {
				return nil, errors.New("not a json object")
			}
			t, err := stringByPath(proofObj, "type")
			if err != nil {
				return nil, err
			}
			if t == proofType {
				return proofObj, nil
			}
		}
	case jsonObj:
		t, err := stringByPath(v, "type")
		if err != nil {
			return nil, err
		}
		if t == proofType {
			return v, nil
		}
	}

	return nil, errors.New("proof not found")
}

var x = map[string]any{}

func atomicQuerySigV2InputsFromJson(
	in []byte) (circuits.AtomicQuerySigV2Inputs, error) {

	var obj jsonObj
	var out circuits.AtomicQuerySigV2Inputs
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return out, err
	}

	out.RequestID, err = bigIntByPath(obj, "request.id", true)
	if err != nil {
		return out, err
	}
	out.ID, err = coreIDByPath(obj, "id")
	if err != nil {
		return out, err
	}
	out.ProfileNonce, err = bigIntByPath(obj, "profileNonce", false)
	if err != nil {
		return out, err
	}
	out.ClaimSubjectProfileNonce, err = bigIntByPath(obj,
		"claimSubjectProfileNonce", false)
	if err != nil {
		return out, err
	}

	circuitID, err := stringByPath(obj, "request.circuitId")
	if err != nil {
		return out, err
	}
	if circuitID != "credentialAtomicQuerySigV2" {
		return out, errors.New("wrong circuit")
	}

	out.Claim, err = claimWithSigProofFromObj(obj)
	if err != nil {
		return out, err
	}

	out.Query, err = queryFromObj(obj)
	if err != nil {
		return out, err
	}

	out.CurrentTimeStamp = time.Now().Unix()

	return out, nil
}

func queryFromObj(obj jsonObj) (out circuits.Query, err error) {
	var claimObj jsonObj
	claimObj, err = objByBath(obj, "verifiableCredentials")
	if err != nil {
		return out, err
	}

	// create new object without proof (proof not need to be merkleized)
	newObj := make(jsonObj, len(claimObj)-1)
	for k, v := range claimObj {
		if k == "proof" {
			continue
		}
		newObj[k] = v
	}
	var claimBytes []byte
	claimBytes, err = json.Marshal(newObj)
	if err != nil {
		return out, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var mz *merklize.Merklizer
	mz, err = merklize.MerklizeJSONLD(ctx, bytes.NewReader(claimBytes))
	if err != nil {
		return out, err
	}

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
	// TODO: is it possible to be more than one field?
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
		// TODO: is it possible to be more than one operation?
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
