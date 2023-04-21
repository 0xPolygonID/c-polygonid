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
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/contracts-abi/state/go/abi"
	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/iden3/go-merkletree-sql/v2"
	json2 "github.com/iden3/go-schema-processor/json"
	"github.com/iden3/go-schema-processor/loaders"
	"github.com/iden3/go-schema-processor/merklize"
	"github.com/iden3/go-schema-processor/processor"
	"github.com/iden3/go-schema-processor/verifiable"
	mp "github.com/iden3/merkletree-proof"
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

type errPathNotFound struct {
	path string
}

func (e errPathNotFound) Error() string {
	return fmt.Sprintf("path not found: %v", e.path)
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
				return nil, errPathNotFound{path}
			}
			return v, nil
		}

		nextObj, ok := curObj[part]
		if !ok {
			return nil, errPathNotFound{path}
		}
		curObj, ok = nextObj.(jsonObj)
		if !ok {
			return nil, errors.New("not a json object")
		}
	}

	return nil, errors.New("should not happen")
}

func resolveRevocationStatusFromIssuerService(ctx context.Context,
	url string) (out circuits.MTProof, err error) {

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

func claimWithSigProofFromObj(ctx context.Context, cfg EnvConfig,
	w3cCred verifiable.W3CCredential,
	skipClaimRevocationCheck bool) (circuits.ClaimWithSigProof, error) {

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
	out.NonRevProof, err = buildAndValidateCredentialStatus(ctx, cfg,
		credStatus, out.IssuerID, skipClaimRevocationCheck)
	if err != nil {
		return out, err
	}
	out.SignatureProof, err = signatureProof(ctx, cfg, *proof, out.IssuerID)
	if err != nil {
		return out, err
	}

	return out, nil
}

func buildAndValidateCredentialStatus(ctx context.Context, cfg EnvConfig,
	credStatus jsonObj, issuerID *core.ID,
	skipClaimRevocationCheck bool) (circuits.MTProof, error) {

	proof, err := resolveRevStatus(ctx, cfg, credStatus, issuerID)
	if err != nil {
		return proof, err
	}

	if skipClaimRevocationCheck {
		return proof, nil
	}

	treeStateOk, err := validateTreeState(proof.TreeState)
	if err != nil {
		return proof, err
	}
	if !treeStateOk {
		return proof, errors.New("invalid tree state")
	}

	// revocationNonce is float64, but if we meet valid string representation
	// of Int, we will use it.
	// circuits.MTProof
	revNonce, err := bigIntByPath(credStatus, "revocationNonce", true)
	if err != nil {
		return proof, err
	}

	proofValid := merkletree.VerifyProof(proof.TreeState.RevocationRoot,
		proof.Proof, revNonce, big.NewInt(0))
	if !proofValid {
		return proof, errors.New("proof validation failed")
	}

	if proof.Proof.Existence {
		return proof, errors.New("credential is revoked")
	}

	return proof, nil
}

// check TreeState consistency
func validateTreeState(s circuits.TreeState) (bool, error) {
	if s.State == nil {
		return false, errors.New("state is nil")
	}

	ctrHash := &merkletree.HashZero
	if s.ClaimsRoot != nil {
		ctrHash = s.ClaimsRoot
	}
	rtrHash := &merkletree.HashZero
	if s.RevocationRoot != nil {
		rtrHash = s.RevocationRoot
	}
	rorHash := &merkletree.HashZero
	if s.RootOfRoots != nil {
		rorHash = s.RootOfRoots
	}

	wantState, err := poseidon.Hash([]*big.Int{ctrHash.BigInt(),
		rtrHash.BigInt(), rorHash.BigInt()})
	if err != nil {
		return false, err
	}

	return wantState.Cmp(s.State.BigInt()) == 0, nil
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

func signatureProof(ctx context.Context, cfg EnvConfig,
	proof verifiable.BJJSignatureProof2021,
	issuerID *core.ID) (out circuits.BJJSignatureProof, err error) {

	out.Signature, err = sigFromHex(proof.Signature)
	if err != nil {
		return out, err
	}
	out.IssuerAuthClaim = new(core.Claim)
	err = out.IssuerAuthClaim.FromHex(proof.IssuerData.AuthCoreClaim)
	if err != nil {
		return
	}
	out.IssuerAuthIncProof.TreeState, err = circuitsTreeStateFromSchemaState(proof.IssuerData.State)
	if err != nil {
		return out, err
	}
	out.IssuerAuthIncProof.Proof = proof.IssuerData.MTP
	credStatus, ok := proof.IssuerData.CredentialStatus.(jsonObj)
	if !ok {
		return out, errors.New("credential status is not of object type")
	}
	out.IssuerAuthNonRevProof, err =
		buildAndValidateCredentialStatus(ctx, cfg, credStatus, issuerID, false)
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

type onChainInputsRequest struct {
	ID                       *core.ID            `json:"id"`
	ProfileNonce             *JsonBigInt         `json:"profileNonce"`
	ClaimSubjectProfileNonce *JsonBigInt         `json:"claimSubjectProfileNonce"`
	AuthClaim                *core.Claim         `json:"authClaim"`
	AuthClaimIncMtp          *merkletree.Proof   `json:"authClaimIncMtp"`
	AuthClaimNonRevMtp       *merkletree.Proof   `json:"authClaimNonRevMtp"`
	TreeState                *circuits.TreeState `json:"treeState"`
	GistProof                *circuits.GISTProof `json:"gistProof"`
	Signature                *hexSigJson         `json:"signature"`
	Challenge                *JsonBigInt         `json:"challenge"`
	VerifiableCredentials    json.RawMessage     `json:"verifiableCredentials"`
	Request                  jsonObj             `json:"request"`
}

type AtomicQueryInputsResponse struct {
	Inputs                 circuits.InputsMarshaller
	VerifiablePresentation map[string]any
}

func AtomicQueryMtpV2InputsFromJson(ctx context.Context, cfg EnvConfig,
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

	inpMarsh.SkipClaimRevocationCheck, err = querySkipRevocation(obj.Request)
	if err != nil {
		return out, err
	}
	inpMarsh.Claim, err = claimWithMtpProofFromObj(ctx, cfg, w3cCred,
		inpMarsh.SkipClaimRevocationCheck)
	if err != nil {
		return out, err
	}

	inpMarsh.Query, out.VerifiablePresentation, err =
		queryFromObj(ctx, w3cCred, obj.Request, inpMarsh.Claim.Claim)
	if err != nil {
		return out, err
	}

	inpMarsh.CurrentTimeStamp = time.Now().Unix()

	out.Inputs = inpMarsh

	return out, nil
}

func verifiablePresentationFromCred(ctx context.Context,
	w3cCred verifiable.W3CCredential, requestObj jsonObj, field string) (
	verifiablePresentation map[string]any, mzValue merklize.Value,
	datatype string, hasher merklize.Hasher, err error) {

	mz, err := w3cCred.Merklize(ctx)
	if err != nil {
		return nil, nil, datatype, hasher, err
	}

	hasher = mz.Hasher()

	var contextType string
	contextType, err = stringByPath(requestObj, "query.type")
	if err != nil {
		return nil, nil, datatype, hasher, err
	}

	var contextURL string
	contextURL, err = stringByPath(requestObj, "query.context")
	if err != nil {
		return nil, nil, datatype, hasher, err
	}

	path, err := buildQueryPath(ctx, contextURL, contextType, field)
	if err != nil {
		return nil, nil, datatype, hasher, err
	}

	datatype, err = mz.JSONLDType(path)
	if err != nil {
		return nil, nil, datatype, hasher, err
	}

	rawValue, err := mz.RawValue(path)
	if err != nil {
		return nil, nil, datatype, hasher, err
	}

	_, mzValue, err = mz.Proof(ctx, path)
	if err != nil {
		return nil, nil, datatype, hasher, err
	}

	verifiablePresentation = fmtVerifiablePresentation(contextURL,
		contextType, field, rawValue)

	return
}

func fmtVerifiablePresentation(context string, tp string, field string,
	value any) map[string]any {

	var ldContext any

	var baseContext = []any{"https://www.w3.org/2018/credentials/v1"}
	if context == baseContext[0] {
		ldContext = baseContext
	} else {
		ldContext = append(baseContext, context)
	}

	vcTypes := []any{"VerifiableCredential"}
	if tp != "VerifiableCredential" {
		vcTypes = append(vcTypes, tp)
	}

	return map[string]any{
		"@context": baseContext,
		"@type":    "VerifiablePresentation",
		"verifiableCredential": map[string]any{
			"@context": ldContext,
			"@type":    vcTypes,
			"credentialSubject": map[string]any{
				"@type": tp,
				field:   value,
			},
		},
	}
}

func AtomicQuerySigV2InputsFromJson(ctx context.Context, cfg EnvConfig,
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

	inpMarsh.SkipClaimRevocationCheck, err = querySkipRevocation(obj.Request)
	if err != nil {
		return out, err
	}
	inpMarsh.Claim, err = claimWithSigProofFromObj(ctx, cfg, w3cCred,
		inpMarsh.SkipClaimRevocationCheck)
	if err != nil {
		return out, err
	}

	inpMarsh.Query, out.VerifiablePresentation, err =
		queryFromObj(ctx, w3cCred, obj.Request, inpMarsh.Claim.Claim)
	if err != nil {
		return out, err
	}

	inpMarsh.CurrentTimeStamp = time.Now().Unix()

	out.Inputs = inpMarsh

	return out, nil
}

func AtomicQueryMtpV2OnChainInputsFromJson(ctx context.Context, cfg EnvConfig,
	in []byte) (AtomicQueryInputsResponse, error) {

	var out AtomicQueryInputsResponse
	var inpMarsh circuits.AtomicQueryMTPV2OnChainInputs

	var obj onChainInputsRequest
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return out, err
	}

	inpMarsh.RequestID, err = bigIntByPath(obj.Request, "id", true)
	if err != nil {
		return out, err
	}

	if obj.ID == nil {
		return out, errors.New(`"id" field is required`)
	}

	inpMarsh.ID = obj.ID
	inpMarsh.ProfileNonce = obj.ProfileNonce.BigInt()
	inpMarsh.ClaimSubjectProfileNonce = obj.ClaimSubjectProfileNonce.BigInt()

	inpMarsh.AuthClaim = obj.AuthClaim
	inpMarsh.AuthClaimIncMtp = obj.AuthClaimIncMtp
	inpMarsh.AuthClaimNonRevMtp = obj.AuthClaimNonRevMtp

	if obj.TreeState == nil {
		return out, errors.New("treeState is required")
	}
	inpMarsh.TreeState = *obj.TreeState

	if obj.GistProof == nil {
		return out, errors.New("gistProof is required")
	}
	inpMarsh.GISTProof = *obj.GistProof

	inpMarsh.Signature = (*babyjub.Signature)(obj.Signature)
	inpMarsh.Challenge = obj.Challenge.BigInt()

	circuitID, err := stringByPath(obj.Request, "circuitId")
	if err != nil {
		return out, err
	}
	if circuitID != string(circuits.AtomicQueryMTPV2OnChainCircuitID) {
		return out, errors.New("wrong circuit")
	}
	var w3cCred verifiable.W3CCredential
	err = json.Unmarshal(obj.VerifiableCredentials, &w3cCred)
	if err != nil {
		return out, err
	}

	inpMarsh.SkipClaimRevocationCheck, err = querySkipRevocation(obj.Request)
	if err != nil {
		return out, err
	}
	inpMarsh.Claim, err = claimWithMtpProofFromObj(ctx, cfg, w3cCred,
		inpMarsh.SkipClaimRevocationCheck)
	if err != nil {
		return out, err
	}

	inpMarsh.Query, out.VerifiablePresentation, err =
		queryFromObj(ctx, w3cCred, obj.Request, inpMarsh.Claim.Claim)
	if err != nil {
		return out, err
	}

	inpMarsh.CurrentTimeStamp = time.Now().Unix()

	out.Inputs = inpMarsh

	return out, nil
}

func AtomicQuerySigV2OnChainInputsFromJson(ctx context.Context, cfg EnvConfig,
	in []byte) (AtomicQueryInputsResponse, error) {

	var out AtomicQueryInputsResponse
	var inpMarsh circuits.AtomicQuerySigV2OnChainInputs

	var obj onChainInputsRequest
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return out, err
	}

	inpMarsh.RequestID, err = bigIntByPath(obj.Request, "id", true)
	if err != nil {
		return out, err
	}

	if obj.ID == nil {
		return out, errors.New(`"id" field is required`)
	}

	inpMarsh.ID = obj.ID
	inpMarsh.ProfileNonce = obj.ProfileNonce.BigInt()
	inpMarsh.ClaimSubjectProfileNonce = obj.ClaimSubjectProfileNonce.BigInt()

	inpMarsh.AuthClaim = obj.AuthClaim
	inpMarsh.AuthClaimIncMtp = obj.AuthClaimIncMtp
	inpMarsh.AuthClaimNonRevMtp = obj.AuthClaimNonRevMtp

	if obj.TreeState == nil {
		return out, errors.New("treeState is required")
	}
	inpMarsh.TreeState = *obj.TreeState

	if obj.GistProof == nil {
		return out, errors.New("gistProof is required")
	}
	inpMarsh.GISTProof = *obj.GistProof

	inpMarsh.Signature = (*babyjub.Signature)(obj.Signature)
	inpMarsh.Challenge = obj.Challenge.BigInt()

	circuitID, err := stringByPath(obj.Request, "circuitId")
	if err != nil {
		return out, err
	}
	if circuitID != string(circuits.AtomicQuerySigV2OnChainCircuitID) {
		return out, errors.New("wrong circuit")
	}
	var w3cCred verifiable.W3CCredential
	err = json.Unmarshal(obj.VerifiableCredentials, &w3cCred)
	if err != nil {
		return out, err
	}

	inpMarsh.SkipClaimRevocationCheck, err = querySkipRevocation(obj.Request)
	if err != nil {
		return out, err
	}
	inpMarsh.Claim, err = claimWithSigProofFromObj(ctx, cfg, w3cCred,
		inpMarsh.SkipClaimRevocationCheck)
	if err != nil {
		return out, err
	}

	inpMarsh.Query, out.VerifiablePresentation, err =
		queryFromObj(ctx, w3cCred, obj.Request, inpMarsh.Claim.Claim)
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

func querySkipRevocation(requestObj jsonObj) (bool, error) {
	result, err := getByPath(requestObj, "query.skipClaimRevocationCheck")
	if errors.As(err, &errPathNotFound{}) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	resB, ok := result.(bool)
	if !ok {
		return false,
			errors.New("value of skipClaimRevocationCheck is not bool")
	}
	return resB, nil
}

func queryFromObj(ctx context.Context, w3cCred verifiable.W3CCredential,
	requestObj jsonObj, claim *core.Claim) (out circuits.Query,
	verifiablePresentation jsonObj, err error) {

	merklizePosition, err := claim.GetMerklizedPosition()
	if err != nil {
		return out, nil, err
	}

	if merklizePosition == core.MerklizedRootPositionNone {
		return queryFromObjNonMerklized(ctx, w3cCred, requestObj)
	}

	return queryFromObjMerklized(ctx, w3cCred, requestObj)
}

func getSchemaLoader(schemaURL string) (processor.SchemaLoader, error) {
	u, err := url.Parse(schemaURL)
	if err != nil {
		return nil, err
	}
	switch u.Scheme {
	case "http", "https":
		return &loaders.HTTP{URL: schemaURL}, nil
	case "ipfs":
		return loaders.IPFS{
			URL: "https://ipfs.io",
			CID: u.Host,
		}, nil
	default:
		return nil, fmt.Errorf("loader for %s is not supported", u.Scheme)
	}
}

func queryFromObjNonMerklized(ctx context.Context,
	w3cCred verifiable.W3CCredential, requestObj jsonObj) (out circuits.Query,
	verifiablePresentation jsonObj, err error) {

	loader, err := getSchemaLoader(w3cCred.CredentialSchema.ID)
	if err != nil {
		return out, nil, err
	}

	pr := processor.InitProcessorOptions(&processor.Processor{
		SchemaLoader: loader,
		Parser:       json2.Parser{},
	})

	schema, _, err := pr.Load(ctx)
	if err != nil {
		return out, nil, err
	}

	field, op, err := getQueryFieldAndOperator(requestObj)
	if errors.As(err, &errPathNotFound{}) {
		out.Operator = circuits.NOOP
		out.Values = []*big.Int{}
		return out, nil, nil
	} else if err != nil {
		return out, nil,
			fmt.Errorf("unable to extract field from query: %w", err)
	}

	out.SlotIndex, err = pr.GetFieldSlotIndex(field, schema)
	if err != nil {
		return out, nil, err
	}

	var opObj jsonObj
	var ok bool
	opObj, ok = op.(jsonObj)
	if !ok {
		return out, nil, errors.New("operation on field is not a json object")
	}

	vp, mzValue, datatype, hasher, err :=
		verifiablePresentationFromCred(ctx, w3cCred, requestObj, field)
	if err != nil {
		return out, nil, err
	}

	opStr, val, err := extractSingleEntry(opObj)
	switch err {
	case errMultipleEntries:
		return out, nil, errors.New("only one operation per field is supported")
	case errNoEntry:
		// handle selective disclosure
		var valueEntry *big.Int
		valueEntry, err = mzValue.MtEntry()
		if err != nil {
			return out, nil, err
		}

		verifiablePresentation = vp
		out.Operator = circuits.EQ
		out.Values = []*big.Int{valueEntry}
	default:
		out.Operator, out.Values, err = unpackOperatorWithArgs(opStr, val,
			datatype, hasher)
		if err != nil {
			return out, nil, err
		}
	}

	return out, verifiablePresentation, nil
}

func queryFromObjMerklized(ctx context.Context,
	w3cCred verifiable.W3CCredential, requestObj jsonObj) (out circuits.Query,
	verifiablePresentation jsonObj, err error) {

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
	field, op, err := getQueryFieldAndOperator(requestObj)
	if errors.As(err, &errPathNotFound{}) {
		out.Operator = circuits.NOOP
		out.Values = []*big.Int{}
		return out, nil, nil
	} else if err != nil {
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
	var mzValue merklize.Value
	out.ValueProof.MTP, mzValue, err = mz.Proof(ctx, path)
	if err != nil {
		return out, nil, err
	}
	out.ValueProof.Value, err = mzValue.MtEntry()
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
		fieldDatatype, err := mz.JSONLDType(path)
		if err != nil {
			return out, nil, err
		}

		out.Operator, out.Values, err = unpackOperatorWithArgs(opStr, val,
			fieldDatatype, mz.Hasher())
		if err != nil {
			return out, nil, err
		}
	}
	return out, verifiablePresentation, nil
}

// Return int operator value by its name and arguments as big.Ints array.
func unpackOperatorWithArgs(opStr string, opValue any,
	datatype string, hasher merklize.Hasher) (int, []*big.Int, error) {

	hashFn := func(val any) (*big.Int, error) {
		if hasher == nil {
			return merklize.HashValue(datatype, val)
		} else {
			return merklize.HashValueWithHasher(hasher, datatype, val)
		}
	}

	op, ok := circuits.QueryOperators[opStr]
	if !ok {
		return 0, nil, errors.New("unknown operator")
	}

	var err error
	valArr, isArr := opValue.([]any)
	if isArr {
		vals := make([]*big.Int, len(valArr))
		for i, v := range valArr {
			vals[i], err = hashFn(v)
			if err != nil {
				return 0, nil, err
			}
		}
		return op, vals, nil
	} else {
		vals := make([]*big.Int, 1)
		vals[0], err = hashFn(opValue)
		if err != nil {
			return 0, nil, err
		}
		return op, vals, nil
	}
}

func getQueryFieldAndOperator(requestObj jsonObj) (string, any, error) {
	credSubjObj, err := objByBath(requestObj, "query.credentialSubject")
	if err != nil {
		return "", nil, err
	}
	return extractSingleEntry(credSubjObj)
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

func claimWithMtpProofFromObj(ctx context.Context, cfg EnvConfig,
	w3cCred verifiable.W3CCredential,
	skipClaimRevocationCheck bool) (circuits.ClaimWithMTPProof, error) {

	var out circuits.ClaimWithMTPProof
	var err error
	var proofI verifiable.CredentialProof
	var issuerDID *core.DID

	if proofI = findProofByType(w3cCred,
		verifiable.Iden3SparseMerkleTreeProofType); proofI != nil {

		proof, ok := proofI.(*verifiable.Iden3SparseMerkleTreeProof)
		if !ok {
			return out, errors.New("proof is not a sparse merkle proof")
		}
		issuerDID, err = core.ParseDID(proof.IssuerData.ID)
		if err != nil {
			return out, err
		}
		out.IncProof.Proof = proof.MTP
		out.IncProof.TreeState, err = circuitsTreeStateFromSchemaState(proof.IssuerData.State)
		if err != nil {
			return out, err
		}

	} else if proofI = findProofByType(w3cCred,
		verifiable.Iden3SparseMerkleProofType); proofI != nil { //nolint:staticcheck //reason: need to support deprecated proofs for backward compatibility

		//nolint:staticcheck //reason: need to support deprecated proofs for backward compatibility
		proof, ok := proofI.(*verifiable.Iden3SparseMerkleProof)
		if !ok {
			return out, errors.New("proof is not a sparse merkle proof")
		}
		issuerDID, err = core.ParseDID(proof.IssuerData.ID)
		if err != nil {
			return out, err
		}
		out.IncProof.Proof = proof.MTP
		out.IncProof.TreeState, err = circuitsTreeStateFromSchemaState(proof.IssuerData.State)
		if err != nil {
			return out, err
		}

	} else {
		return out, fmt.Errorf("no %v proofs found",
			verifiable.Iden3SparseMerkleTreeProofType)
	}

	out.IssuerID = &issuerDID.ID
	if err != nil {
		return out, err
	}

	out.Claim, err = proofI.GetCoreClaim()
	if err != nil {
		return out, err
	}

	credStatus, ok := w3cCred.CredentialStatus.(jsonObj)
	if !ok {
		return out, errors.New("not a json object")
	}

	out.NonRevProof, err = buildAndValidateCredentialStatus(ctx, cfg,
		credStatus, out.IssuerID, skipClaimRevocationCheck)
	if err != nil {
		return out, err
	}

	return out, nil
}

func circuitsTreeStateFromSchemaState(
	state verifiable.State) (ts circuits.TreeState, err error) {

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

func resolveRevStatus(ctx context.Context,
	cfg EnvConfig, credStatus interface{},
	issuerID *core.ID) (circuits.MTProof, error) {

	switch status := credStatus.(type) {
	case *verifiable.RHSCredentialStatus:
		revNonce := new(big.Int).SetUint64(status.RevocationNonce)
		return resolveRevStatusFromRHS(ctx, cfg, issuerID, revNonce)
	case *verifiable.CredentialStatus:
		return resolveRevocationStatusFromIssuerService(ctx, status.ID)
	case verifiable.RHSCredentialStatus:
		return resolveRevStatus(ctx, cfg, &status, issuerID)
	case verifiable.CredentialStatus:
		return resolveRevStatus(ctx, cfg, &status, issuerID)
	case map[string]interface{}:
		credStatusType, ok := status["type"].(string)
		if !ok {
			return circuits.MTProof{},
				errors.New("credential status doesn't contain type")
		}
		marshaledStatus, err := json.Marshal(status)
		if err != nil {
			return circuits.MTProof{}, err
		}
		var s interface{}
		switch verifiable.CredentialStatusType(credStatusType) {
		case verifiable.Iden3ReverseSparseMerkleTreeProof:
			s = &verifiable.RHSCredentialStatus{}
		case verifiable.SparseMerkleTreeProof:
			s = &verifiable.CredentialStatus{}
		default:
			return circuits.MTProof{}, fmt.Errorf(
				"credential status type %s id not supported",
				credStatusType)
		}

		err = json.Unmarshal(marshaledStatus, s)
		if err != nil {
			return circuits.MTProof{}, err
		}
		return resolveRevStatus(ctx, cfg, s, issuerID)

	default:
		return circuits.MTProof{},
			errors.New("unknown credential status format")
	}
}

type EnvConfig struct {
	EthereumURL           string
	StateContractAddr     common.Address
	ReverseHashServiceUrl string
}

// Currently, our library does not have a Close function. As a result, we
// create and destroy an Ethereum client for each usage of this function.
// Although this approach may be inefficient, it is acceptable if the function
// is rarely called. If this becomes an issue in the future, or if a Close
// function is implemented, we will need to refactor this function to use a
// global Ethereum client.
func lastStateFromContract(ctx context.Context, ethURL string,
	contractAddr common.Address, id *core.ID) (*merkletree.Hash, error) {
	if ethURL == "" {
		return nil, errors.New("ethereum url is empty")
	}

	if contractAddr == (common.Address{}) {
		return nil, errors.New("contract address is empty")
	}

	var zeroID core.ID
	if id == nil || *id == zeroID {
		return nil, errors.New("ID is empty")
	}

	client, err := ethclient.Dial(ethURL)
	if err != nil {
		return nil, err
	}
	defer client.Close()

	contractCaller, err := abi.NewStateCaller(contractAddr, client)
	if err != nil {
		return nil, err
	}

	resp, err := contractCaller.GetStateInfoById(
		&bind.CallOpts{Context: ctx},
		id.BigInt())
	if err != nil {
		return nil, err
	}

	if resp.State == nil {
		return nil, errors.New("got nil state from contract")
	}

	return merkletree.NewHashFromBigInt(resp.State)
}

func newRhsCli(rhsURL string) (*mp.HTTPReverseHashCli, error) {
	if rhsURL == "" {
		return nil, errors.New("reverse hash service url is empty")
	}

	return &mp.HTTPReverseHashCli{
		URL:         rhsURL,
		HTTPTimeout: 10 * time.Second,
	}, nil
}

func treeStateFromRHS(ctx context.Context, rhsCli *mp.HTTPReverseHashCli,
	state *merkletree.Hash) (circuits.TreeState, error) {

	var treeState circuits.TreeState

	stateNode, err := rhsCli.GetNode(ctx, state)
	if err != nil {
		return treeState, err
	}

	if len(stateNode.Children) != 3 {
		return treeState, errors.New(
			"invalid state node, should have 3 children")
	}

	treeState.State = state
	treeState.ClaimsRoot = stateNode.Children[0]
	treeState.RevocationRoot = stateNode.Children[1]
	treeState.RootOfRoots = stateNode.Children[2]

	return treeState, err
}

func resolveRevStatusFromRHS(ctx context.Context, cfg EnvConfig,
	issuerID *core.ID, revNonce *big.Int) (circuits.MTProof, error) {

	var p circuits.MTProof

	state, err := lastStateFromContract(ctx, cfg.EthereumURL,
		cfg.StateContractAddr, issuerID)
	if err != nil {
		return p, err
	}

	rhsCli, err := newRhsCli(cfg.ReverseHashServiceUrl)
	if err != nil {
		return p, err
	}

	p.TreeState, err = treeStateFromRHS(ctx, rhsCli, state)
	if err != nil {
		return p, err
	}

	revNonceHash, err := merkletree.NewHashFromBigInt(revNonce)
	if err != nil {
		return p, err
	}

	p.Proof, err = rhsCli.GenerateProof(ctx, p.TreeState.RevocationRoot,
		revNonceHash)
	if err != nil {
		return p, err
	}

	return p, nil
}
