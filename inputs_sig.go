package c_polygonid

import (
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"runtime/trace"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	gocircuitexternal "github.com/0xPolygonID/go-circuit-external/AnonAadhaar"
	externalpassport "github.com/0xPolygonID/go-circuit-external/passport"
	"github.com/dgraph-io/badger/v4"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/iden3/go-merkletree-sql/v2"
	json2 "github.com/iden3/go-schema-processor/v2/json"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/processor"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	i3cResolvers "github.com/iden3/iden3comm/v2/resolvers"
	"github.com/iden3/merkletree-proof/resolvers"
	"github.com/piprate/json-gold/ld"
)

const mtLevels = 40

type jsonObj = map[string]any

//go:embed schemas/credentials-v1.json-ld
var credentialsV1JsonLDBytes []byte

var errCredentialsRevoked = errors.New("credential is revoked")

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

func bigIntOrZeroByPath(obj jsonObj, path string,
	allowNumbers bool) (*big.Int, error) {

	i, err := bigIntByPath(obj, path, allowNumbers)
	if errors.As(err, &errPathNotFound{}) {
		return big.NewInt(0), nil
	}
	return i, err
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

type errProofNotFound verifiable.ProofType

func (e errProofNotFound) Error() string {
	return fmt.Sprintf("proof not found: %v", string(e))
}

func claimWithSigProofFromObj(ctx context.Context, cfg EnvConfig,
	w3cCred verifiable.W3CCredential,
	skipClaimRevocationCheck bool) (circuits.ClaimWithSigProof, error) {

	var out circuits.ClaimWithSigProof

	proofI := findProofByType(w3cCred, verifiable.BJJSignatureProofType)
	if proofI == nil {
		return out, errProofNotFound(verifiable.BJJSignatureProofType)
	}

	var err error
	proof, ok := proofI.(*verifiable.BJJSignatureProof2021)
	if !ok {
		return out, errors.New("proof is not of type BJJSignatureProof2021")
	}
	issuerDID, err := w3c.ParseDID(proof.IssuerData.ID)
	if err != nil {
		return out, err
	}
	issuerID, err := core.IDFromDID(*issuerDID)
	if err != nil {
		return out, fmt.Errorf("can't get issuer ID from DID (%v): %w",
			issuerDID, err)
	}
	out.IssuerID = &issuerID
	out.Claim, err = proof.GetCoreClaim()
	if err != nil {
		return out, err
	}

	credStatus, ok := w3cCred.CredentialStatus.(jsonObj)
	if !ok {
		return out, errors.New("not a json object")
	}
	userDID, err := userDIDFromCred(w3cCred)
	if err != nil {
		return out, err
	}

	out.NonRevProof, err = buildAndValidateCredentialStatus(ctx, cfg,
		credStatus, issuerDID, userDID, skipClaimRevocationCheck)
	if err != nil {
		return out, ErrCredentialStatus{
			err:   err,
			owner: CredentialStatusOwnerUser,
		}
	}
	out.SignatureProof, err = signatureProof(ctx, cfg, *proof, issuerDID,
		userDID)
	if err != nil {
		return out, err
	}

	return out, nil
}

// returned DID maybe nil if we do not find it in the credential
func userDIDFromCred(w3cCred verifiable.W3CCredential) (*w3c.DID, error) {
	if userDIDi, ok := w3cCred.CredentialSubject["id"]; ok {
		var userDIDs string
		userDIDs, ok = userDIDi.(string)
		if ok {
			userDID, err := w3c.ParseDID(userDIDs)
			if err != nil {
				return nil, fmt.Errorf(
					"error parsing user DID from credentialSubject.id field: %w",
					err)
			}
			return userDID, nil
		} else {
			return nil, errors.New(
				"credentialSubject.id field supposed to be a string type and in DID format")
		}
	}
	return nil, nil
}

func getResolversRegistry(ctx context.Context,
	cfg PerChainConfig) (*verifiable.CredentialStatusResolverRegistry, func(), error) {

	var ethClients = make(map[core.ChainID]*ethclient.Client, len(cfg))
	var stateContractAddresses = make(map[core.ChainID]common.Address, len(cfg))
	var registry = &verifiable.CredentialStatusResolverRegistry{}

	cleanupFn := func() {
		registry.Delete(verifiable.SparseMerkleTreeProof)
		registry.Delete(verifiable.Iden3ReverseSparseMerkleTreeProof)
		registry.Delete(verifiable.Iden3OnchainSparseMerkleTreeProof2023)
		registry.Delete(verifiable.Iden3commRevocationStatusV1)

		for _, cli := range ethClients {
			cli.Close()
		}
	}

	for chainID, chainCfg := range cfg {
		err := chainCfg.validate()
		if err != nil {
			cleanupFn()
			return nil, nil, fmt.Errorf(
				"chain config validation failed for chain ID %v: %w",
				chainID, err)
		}

		ethCli, err := ethclient.DialContext(ctx, chainCfg.RPCUrl)
		if err != nil {
			cleanupFn()
			return nil, nil, err
		}

		ethClients[chainID] = ethCli
		stateContractAddresses[chainID] = chainCfg.StateContractAddr
	}

	registry.Register(verifiable.SparseMerkleTreeProof,
		verifiable.IssuerResolver{})

	rhsResolver := resolvers.NewRHSResolver(ethClients, stateContractAddresses)
	registry.Register(verifiable.Iden3ReverseSparseMerkleTreeProof, rhsResolver)

	onChainRHSResolver := resolvers.NewOnChainResolver(ethClients,
		stateContractAddresses)
	registry.Register(verifiable.Iden3OnchainSparseMerkleTreeProof2023,
		onChainRHSResolver)

	pm := iden3comm.NewPackageManager()
	err := pm.RegisterPackers(&packers.PlainMessagePacker{})
	if err != nil {
		cleanupFn()
		return nil, nil, err
	}
	iden3comResolver := i3cResolvers.NewAgentResolver(
		i3cResolvers.AgentResolverConfig{PackageManager: pm})
	registry.Register(verifiable.Iden3commRevocationStatusV1, iden3comResolver)

	return registry, cleanupFn, nil
}

func stringToHash(h string) (*merkletree.Hash, error) {
	if h == "" {
		return nil, nil
	}
	return merkletree.NewHashFromHex(h)
}

func verifiableTreeStateToCircuitsTreeState(
	s verifiable.TreeState) (circuits.TreeState, error) {

	var err error
	var out circuits.TreeState

	out.ClaimsRoot = &merkletree.HashZero
	out.RootOfRoots = &merkletree.HashZero
	out.RevocationRoot = &merkletree.HashZero

	if s.State != nil {
		out.State, err = stringToHash(*s.State)
		if err != nil {
			return out, fmt.Errorf("can't parse state: %w", err)
		}
	}

	if s.ClaimsTreeRoot != nil {
		out.ClaimsRoot, err = stringToHash(*s.ClaimsTreeRoot)
		if err != nil {
			return out, fmt.Errorf("can't parse claims tree root: %w", err)
		}
	}

	if s.RevocationTreeRoot != nil {
		out.RevocationRoot, err = stringToHash(*s.RevocationTreeRoot)
		if err != nil {
			return out, fmt.Errorf("can't parse revocation tree root: %w", err)
		}
	}

	if s.RootOfRoots != nil {
		out.RootOfRoots, err = stringToHash(*s.RootOfRoots)
		if err != nil {
			return out, fmt.Errorf("can't parse root of roots tree root: %w", err)
		}
	}

	return out, nil
}

func revStatusToCircuitsMTPProof(
	revStatus verifiable.RevocationStatus) (circuits.MTProof, error) {

	p := circuits.MTProof{Proof: &revStatus.MTP}
	var err error
	p.TreeState, err = verifiableTreeStateToCircuitsTreeState(revStatus.Issuer)
	if err != nil {
		return p, fmt.Errorf(
			"can't convert verifiable.TreeState to circuits.TreeState: %w", err)
	}

	return p, nil
}

func buildAndValidateCredentialStatus(ctx context.Context, cfg EnvConfig,
	credStatus jsonObj, issuerDID, userDID *w3c.DID,
	skipClaimRevocationCheck bool) (circuits.MTProof, error) {

	credStatus2, err := credStatusFromJsonObj(credStatus)
	if err != nil {
		return circuits.MTProof{}, ErrCredentialStatusExtract{err: err}
	}

	revStatus, err := cachedResolve(ctx, cfg, issuerDID, userDID,
		credStatus2, getResolversRegistry)
	if err != nil {
		return circuits.MTProof{}, ErrCredentialStatusResolve{err: err}
	}

	cProof, err := revStatusToCircuitsMTPProof(revStatus)
	if err != nil {
		return circuits.MTProof{}, ErrCredentialStatusTreeBuild{err: err}
	}

	if skipClaimRevocationCheck {
		return cProof, nil
	}

	treeStateOk, err := validateTreeState(cProof.TreeState)
	if err != nil {
		return circuits.MTProof{},
			ErrCredentialStatusTreeState{
				msg: "tree state validation failed",
				err: err,
			}
	}
	if !treeStateOk {
		return circuits.MTProof{},
			ErrCredentialStatusTreeState{
				msg: "invalid tree state",
				err: err,
			}

	}

	revNonce := new(big.Int).SetUint64(credStatus2.RevocationNonce)

	proofValid := merkletree.VerifyProof(cProof.TreeState.RevocationRoot,
		cProof.Proof, revNonce, big.NewInt(0))
	if !proofValid {
		return circuits.MTProof{}, ErrCredentialStatusTreeState{
			msg: "proof validation failed",
		}
	}

	if cProof.Proof.Existence {
		return circuits.MTProof{}, ErrCredentialStatusRevoked
	}

	return cProof, nil
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
	proof verifiable.BJJSignatureProof2021, issuerDID,
	userDID *w3c.DID) (out circuits.BJJSignatureProof, err error) {

	out.Signature, err = sigFromHex(proof.Signature)
	if err != nil {
		return out, err
	}
	out.IssuerAuthClaim = new(core.Claim)
	err = out.IssuerAuthClaim.FromHex(proof.IssuerData.AuthCoreClaim)
	if err != nil {
		return out, err
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
		buildAndValidateCredentialStatus(ctx, cfg, credStatus, issuerDID,
			userDID, false)
	if err != nil {
		return out, ErrCredentialStatus{
			err:   err,
			owner: CredentialStatusOwnerIssuer,
		}
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

type v3InputsRequest struct {
	inputsRequest
	VerifierID *w3c.DID   `json:"verifierId"`
	LinkNonce  JsonBigInt `json:"linkNonce"`
}

type linkedMultiQueryInputsRequest struct {
	inputsRequest
	LinkNonce *JsonBigInt `json:"linkNonce"`
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

type txData struct {
	ContractAddress common.Address `json:"contractAddress"`
	ChainID         core.ChainID   `json:"chainId"`
}

type v3OnChainInputsRequest struct {
	onChainInputsRequest
	VerifierID *w3c.DID   `json:"verifierId"`
	LinkNonce  JsonBigInt `json:"linkNonce"`
	TxData     *txData    `json:"transactionData"`
}

type AtomicQueryInputsResponse struct {
	Inputs                 circuits.InputsMarshaller
	VerifiablePresentation map[string]any
	CircuitID              circuits.CircuitID
}

func AtomicQueryMtpV2InputsFromJson(ctx context.Context, cfg EnvConfig,
	in []byte) (AtomicQueryInputsResponse, error) {

	ctx, task := trace.NewTask(ctx, "AtomicQueryMtpV2InputsFromJson")
	defer task.End()

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

	circuitID, err := getCircuitID(obj.Request)
	if err != nil {
		return out, err
	}
	if circuitID != circuits.AtomicQueryMTPV2CircuitID {
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

	var wg sync.WaitGroup

	var queryErr error
	var proofErr error

	onClaimReady := func(claim *core.Claim) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			inpMarsh.Query, out.VerifiablePresentation, queryErr = queryFromObj(
				ctx, w3cCred, obj.Request, claim, cfg.documentLoader(),
				circuitID, cfg.CacheDir)
			slog.Debug("query done in", "time", time.Since(start))
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		start := time.Now()
		inpMarsh.Claim, proofErr = claimWithMtpProofFromObj(ctx, cfg, w3cCred,
			inpMarsh.SkipClaimRevocationCheck, onClaimReady)
		slog.Debug("rev proof done in", "time", time.Since(start))
	}()

	wg.Wait()
	if proofErr != nil {
		return out, proofErr
	}
	if queryErr != nil {
		return out, queryErr
	}

	inpMarsh.CurrentTimeStamp = time.Now().Unix()

	out.Inputs = inpMarsh

	return out, nil
}

type objEntry struct {
	key   string
	value any
}

func mkVPObj(tp string, kvs ...objEntry) (jsonObj, error) {
	out := jsonObj{"type": tp}
	for _, kv := range kvs {
		err := insertKV(out, kv)
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func insertKV(obj jsonObj, kv objEntry) error {
	if kv.key == "" {
		return errors.New("empty key")
	}

	idx := strings.Index(kv.key, ".")
	if idx == -1 {
		if _, ok := obj[kv.key]; ok {
			return fmt.Errorf("key already exists: %v", kv.key)
		}

		obj[kv.key] = kv.value
		return nil
	}

	if idx == 0 || idx == len(kv.key)-1 {
		return fmt.Errorf("invalid key with an empty part: %v", kv.key)
	}

	var nestedObj jsonObj
	nestedObjI, ok := obj[kv.key[:idx]]
	if !ok {
		nestedObj = make(jsonObj)
		obj[kv.key[:idx]] = nestedObj
	} else {
		nestedObj, ok = nestedObjI.(jsonObj)
		if !ok {
			return fmt.Errorf("not a json object: %v", kv.key[:idx])
		}
	}
	return insertKV(nestedObj, objEntry{key: kv.key[idx+1:], value: kv.value})
}

func fmtVerifiablePresentation(context string, tp string,
	kvs ...objEntry) (map[string]any, error) {

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

	credSubject, err := mkVPObj(tp, kvs...)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"@context": baseContext,
		"type":     "VerifiablePresentation",
		"verifiableCredential": map[string]any{
			"@context":          ldContext,
			"type":              vcTypes,
			"credentialSubject": credSubject,
		},
	}, nil
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

	circuitID, err := getCircuitID(obj.Request)
	if err != nil {
		return out, err
	}
	if circuitID != circuits.AtomicQuerySigV2CircuitID {
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

	inpMarsh.Query, out.VerifiablePresentation, err = queryFromObj(ctx, w3cCred,
		obj.Request, inpMarsh.Claim.Claim, cfg.documentLoader(), circuitID,
		cfg.CacheDir)
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

	circuitID, err := getCircuitID(obj.Request)
	if err != nil {
		return out, err
	}
	if circuitID != circuits.AtomicQueryMTPV2OnChainCircuitID {
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

	var wg sync.WaitGroup

	var queryErr error
	var proofErr error

	onClaimReady := func(claim *core.Claim) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			inpMarsh.Query, out.VerifiablePresentation, queryErr = queryFromObj(
				ctx, w3cCred, obj.Request, claim, cfg.documentLoader(),
				circuitID, cfg.CacheDir)
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		inpMarsh.Claim, proofErr = claimWithMtpProofFromObj(ctx, cfg, w3cCred,
			inpMarsh.SkipClaimRevocationCheck, onClaimReady)
	}()

	wg.Wait()
	if proofErr != nil {
		return out, proofErr
	}
	if queryErr != nil {
		return out, queryErr
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

	circuitID, err := getCircuitID(obj.Request)
	if err != nil {
		return out, err
	}
	if circuitID != circuits.AtomicQuerySigV2OnChainCircuitID {
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

	inpMarsh.Query, out.VerifiablePresentation, err = queryFromObj(ctx, w3cCred,
		obj.Request, inpMarsh.Claim.Claim, cfg.documentLoader(), circuitID,
		cfg.CacheDir)
	if err != nil {
		return out, err
	}

	inpMarsh.CurrentTimeStamp = time.Now().Unix()

	out.Inputs = inpMarsh

	return out, nil
}

func AtomicQueryV3OnChainInputsFromJson(ctx context.Context, cfg EnvConfig,
	in []byte) (AtomicQueryInputsResponse, error) {
	return atomicQueryV3OnChainInputsFromJson(ctx, cfg, in,
		[]circuits.CircuitID{circuits.AtomicQueryV3OnChainCircuitID}, false)
}

func atomicQueryV3OnChainInputsFromJson(ctx context.Context, cfg EnvConfig,
	in []byte, validCircuitIDs []circuits.CircuitID,
	adjustForMinCircuit bool) (AtomicQueryInputsResponse, error) {

	var out AtomicQueryInputsResponse
	var inpMarsh circuits.AtomicQueryV3OnChainInputs
	inpMarsh.IsBJJAuthEnabled = 1

	var obj v3OnChainInputsRequest
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

	circuitID, err := getCircuitID(obj.Request)
	if err != nil {
		return out, err
	}
	if !slices.Contains(validCircuitIDs, circuitID) {
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

	reqProofType, err := queryProofType(obj.Request)
	if err != nil {
		return out, err
	}

	inpMarsh.Claim, inpMarsh.ProofType, err = claimWithSigAndMtpProofFromObj(
		ctx, cfg, w3cCred, inpMarsh.SkipClaimRevocationCheck, reqProofType)
	if err != nil {
		return out, err
	}

	inpMarsh.Query, out.VerifiablePresentation, err = queryFromObj(ctx, w3cCred,
		obj.Request, inpMarsh.Claim.Claim, cfg.documentLoader(), circuitID,
		cfg.CacheDir)
	if err != nil {
		return out, err
	}

	inpMarsh.CurrentTimeStamp = time.Now().Unix()

	inpMarsh.LinkNonce = obj.LinkNonce.BigInt()
	if obj.VerifierID != nil {
		id, err := core.IDFromDID(*obj.VerifierID)
		if err != nil {
			return out, err
		}
		inpMarsh.VerifierID = &id
	} else {
		inpMarsh.VerifierID = &core.ID{}
	}

	inpMarsh.NullifierSessionID, err = bigIntOrZeroByPath(obj.Request,
		"params.nullifierSessionId", true)
	if err != nil {
		return out, err
	}

	if adjustForMinCircuit {
		out.CircuitID, err = circuits.AdjustInputsForMinCircuit(&inpMarsh)
		if err != nil {
			return out, fmt.Errorf("failed to adjust inputs for min circuit: %w", err)
		}
	}

	out.Inputs = inpMarsh

	return out, nil
}

func AtomicQueryV3InputsFromJson(ctx context.Context, cfg EnvConfig,
	in []byte) (AtomicQueryInputsResponse, error) {
	return atomicQueryV3InputsFromJson(ctx, cfg, in,
		[]circuits.CircuitID{circuits.AtomicQueryV3CircuitID}, false)
}

func atomicQueryV3InputsFromJson(ctx context.Context, cfg EnvConfig,
	in []byte, validCircuitIDs []circuits.CircuitID,
	adjustForMinCircuit bool) (AtomicQueryInputsResponse, error) {

	var out AtomicQueryInputsResponse
	var inpMarsh circuits.AtomicQueryV3Inputs

	var obj v3InputsRequest
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

	circuitID, err := getCircuitID(obj.Request)
	if err != nil {
		return out, err
	}
	if !slices.Contains(validCircuitIDs, circuitID) {
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

	reqProofType, err := queryProofType(obj.Request)
	if err != nil {
		return out, err
	}

	inpMarsh.Claim, inpMarsh.ProofType, err = claimWithSigAndMtpProofFromObj(
		ctx, cfg, w3cCred, inpMarsh.SkipClaimRevocationCheck, reqProofType)
	if err != nil {
		return out, err
	}

	inpMarsh.Query, out.VerifiablePresentation, err = queryFromObj(ctx, w3cCred,
		obj.Request, inpMarsh.Claim.Claim, cfg.documentLoader(), circuitID,
		cfg.CacheDir)
	if err != nil {
		return out, err
	}

	inpMarsh.CurrentTimeStamp = time.Now().Unix()

	inpMarsh.NullifierSessionID, err = bigIntOrZeroByPath(obj.Request,
		"params.nullifierSessionId", true)
	if err != nil {
		return out, err
	}

	if obj.VerifierID != nil {
		id, err := core.IDFromDID(*obj.VerifierID)
		if err != nil {
			return out, err
		}
		inpMarsh.VerifierID = &id
	} else {
		inpMarsh.VerifierID = &core.ID{}
	}

	inpMarsh.LinkNonce = obj.LinkNonce.BigInt()

	if adjustForMinCircuit {
		out.CircuitID, err = circuits.AdjustInputsForMinCircuit(&inpMarsh)
		if err != nil {
			return out, fmt.Errorf("failed to adjust inputs for min circuit: %w", err)
		}
	}

	out.Inputs = inpMarsh

	return out, nil
}

func GenericInputsFromJson(ctx context.Context, cfg EnvConfig,
	in []byte) (AtomicQueryInputsResponse, error) {
	var req struct {
		Request struct {
			CircuitID circuits.CircuitID `json:"circuitId"`
		} `json:"request"`
	}

	err := json.Unmarshal(in, &req)
	if err != nil {
		return AtomicQueryInputsResponse{}, err
	}

	switch req.Request.CircuitID {
	case circuits.AtomicQueryMTPV2CircuitID:
		return AtomicQueryMtpV2InputsFromJson(ctx, cfg, in)
	case circuits.AtomicQuerySigV2CircuitID:
		return AtomicQuerySigV2InputsFromJson(ctx, cfg, in)
	case circuits.AtomicQueryMTPV2OnChainCircuitID:
		return AtomicQueryMtpV2OnChainInputsFromJson(ctx, cfg, in)
	case circuits.AtomicQuerySigV2OnChainCircuitID:
		return AtomicQuerySigV2OnChainInputsFromJson(ctx, cfg, in)
	case circuits.AtomicQueryV3CircuitID:
		return AtomicQueryV3InputsFromJson(ctx, cfg, in)
	case circuits.AtomicQueryV3OnChainCircuitID:
		return AtomicQueryV3OnChainInputsFromJson(ctx, cfg, in)
	case circuits.AtomicQueryV3StableCircuitID:
		return atomicQueryV3InputsFromJson(ctx, cfg, in,
			[]circuits.CircuitID{circuits.AtomicQueryV3StableCircuitID}, true)
	case circuits.AtomicQueryV3OnChainStableCircuitID:
		return atomicQueryV3OnChainInputsFromJson(ctx, cfg, in,
			[]circuits.CircuitID{circuits.AtomicQueryV3OnChainStableCircuitID}, true)
	case circuits.LinkedMultiQuery10CircuitID:
		return LinkedMultiQueryInputsFromJson(ctx, cfg, in)
	case circuits.AuthV2CircuitID:
		authCfg := circuits.BaseConfig{}
		return AuthInputsFromJson[circuits.AuthV2Inputs](in, authCfg)
case circuits.AuthV3CircuitID, circuits.AuthV3_8_32CircuitID:
		return AuthInputsFromJson[circuits.AuthV3Inputs](in, circuits.BaseConfig{})
	case gocircuitexternal.AnonAadhaarV1:
		return AnonAadhaarInputsFromJson(ctx, cfg, in)
	case externalpassport.CredentialSHA1,
		externalpassport.CredentialSHA224,
		externalpassport.CredentialSHA256,
		externalpassport.CredentialSHA384,
		externalpassport.CredentialSHA512:
		return PassportInputsFromJson(ctx, cfg, in)
	}

	return AtomicQueryInputsResponse{}, errors.New("unknown circuit")
}

func LinkedMultiQueryInputsFromJson(ctx context.Context, cfg EnvConfig,
	in []byte) (AtomicQueryInputsResponse, error) {

	var out AtomicQueryInputsResponse
	var inpMarsh circuits.LinkedMultiQueryInputs

	var obj linkedMultiQueryInputsRequest
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return out, err
	}

	if obj.LinkNonce == nil {
		return out, errors.New(`"linkNonce" field is required`)
	}
	inpMarsh.LinkNonce = obj.LinkNonce.BigInt()

	circuitID, err := getCircuitID(obj.Request)
	if err != nil {
		return out, err
	}
	if circuitID != circuits.LinkedMultiQuery10CircuitID {
		return out, errors.New("wrong circuit")
	}

	var w3cCred verifiable.W3CCredential
	err = json.Unmarshal(obj.VerifiableCredentials, &w3cCred)
	if err != nil {
		return out, err
	}

	reqProofType, err := queryProofType(obj.Request)
	if err != nil {
		return out, err
	}

	claim, _, err := claimWithSigAndMtpProofFromObj(ctx, cfg, w3cCred, true,
		reqProofType)
	if err != nil {
		return out, err
	}

	inpMarsh.Claim = claim.Claim

	inpMarsh.Query, out.VerifiablePresentation, err = queriesFromObj(ctx,
		w3cCred, obj.Request, inpMarsh.Claim, cfg.documentLoader(), circuitID,
		cfg.CacheDir)
	if err != nil {
		return out, err
	}

	out.Inputs = inpMarsh

	return out, nil
}

// return empty circuits.ProofType if not found
func queryProofType(requestObj jsonObj) (circuits.ProofType, error) {
	result, err := getByPath(requestObj, "query.proofType")
	if errors.As(err, &errPathNotFound{}) {
		return "", nil
	}
	if err != nil {
		return "", err
	}

	resS, ok := result.(string)
	if !ok {
		return "", errors.New("value of proofType is not string")
	}

	switch circuits.ProofType(resS) {
	case circuits.Iden3SparseMerkleTreeProofType:
		return circuits.Iden3SparseMerkleTreeProofType, nil
	case circuits.BJJSignatureProofType:
		return circuits.BJJSignatureProofType, nil
	}
	return "", fmt.Errorf("unknown proofType: %v", resS)

}

func buildQueryPath(_ context.Context, contextURL string, contextType string,
	field string,
	documentLoader ld.DocumentLoader) (path merklize.Path, err error) {

	schemaDoc, err := documentLoader.LoadDocument(contextURL)
	if err != nil {
		return merklize.Path{}, err
	}

	schemaBytes, err := json.Marshal(schemaDoc.Document)
	if err != nil {
		return merklize.Path{}, err
	}
	path, err = merklize.NewFieldPathFromContext(schemaBytes, contextType,
		field)
	if err != nil {
		return
	}
	// took from identity-server prepareMerklizedQuery func
	err = path.Prepend(iriCredentialSubject)
	if err != nil {
		return
	}

	return
}

func datatypeFromContext(contextURL string, contextType string, field string,
	documentLoader ld.DocumentLoader, hasher merklize.Hasher) (string, error) {

	return merklize.Options{
		Hasher:         hasher,
		DocumentLoader: documentLoader,
	}.TypeFromContext(
		[]byte(`{"@context":"`+contextURL+`"}`),
		contextType+"."+field)
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
	requestObj jsonObj, claim *core.Claim, documentLoader ld.DocumentLoader,
	circuitID circuits.CircuitID, cacheDir string) (out circuits.Query,
	verifiablePresentation jsonObj, err error) {

	merklizePosition, err := claim.GetMerklizedPosition()
	if err != nil {
		return out, nil, err
	}

	var queries []*circuits.Query
	var vp jsonObj
	if merklizePosition == core.MerklizedRootPositionNone {
		queries, vp, err = queriesFromObjNonMerklized(ctx, w3cCred, requestObj,
			documentLoader, circuitID, cacheDir)
	} else {
		queries, vp, err = queriesFromObjMerklized(ctx, w3cCred, requestObj,
			documentLoader, circuitID, claim, cacheDir)
	}
	if err != nil {
		return circuits.Query{}, nil, err
	}

	for i := 1; i < len(queries); i++ {
		if queries[i] != nil {
			return circuits.Query{}, nil,
				errors.New("multiple queries are not supported")
		}
	}

	if len(queries) == 0 || queries[0] == nil {
		// we should not reach here
		return circuits.Query{}, nil, errors.New("[assertion] no query found")
	}

	return *queries[0], vp, nil
}

func queriesFromObj(ctx context.Context, w3cCred verifiable.W3CCredential,
	requestObj jsonObj, claim *core.Claim, documentLoader ld.DocumentLoader,
	circuitID circuits.CircuitID, cacheDir string) ([]*circuits.Query, jsonObj, error) {

	merklizePosition, err := claim.GetMerklizedPosition()
	if err != nil {
		return nil, nil, err
	}

	if merklizePosition == core.MerklizedRootPositionNone {
		return queriesFromObjNonMerklized(ctx, w3cCred, requestObj,
			documentLoader, circuitID, cacheDir)
	}

	return queriesFromObjMerklized(ctx, w3cCred, requestObj, documentLoader,
		circuitID, claim, cacheDir)
}

func wrapMerklizeWithRegion(ctx context.Context,
	w3cCred verifiable.W3CCredential, documentLoader ld.DocumentLoader,
	cacheDir string) (*merklize.Merklizer, error) {

	var mz *merklize.Merklizer
	var err error
	trace.WithRegion(ctx, "merklize", func() {
		mz, err = merklizeCred(ctx, w3cCred, documentLoader, true, cacheDir)
	})
	return mz, err
}

func isV2Circuit(circuitID circuits.CircuitID) bool {
	return circuitID == circuits.AtomicQueryMTPV2CircuitID ||
		circuitID == circuits.AtomicQueryMTPV2OnChainCircuitID ||
		circuitID == circuits.AtomicQuerySigV2CircuitID ||
		circuitID == circuits.AtomicQuerySigV2OnChainCircuitID
}

var sdOperator = map[circuits.CircuitID]int{
	circuits.AtomicQueryMTPV2CircuitID:        circuits.EQ,
	circuits.AtomicQueryMTPV2OnChainCircuitID: circuits.EQ,
	circuits.AtomicQuerySigV2CircuitID:        circuits.EQ,
	circuits.AtomicQuerySigV2OnChainCircuitID: circuits.EQ,
	circuits.AtomicQueryV3CircuitID:           circuits.SD,
	circuits.AtomicQueryV3OnChainCircuitID:    circuits.SD,
	circuits.LinkedMultiQuery10CircuitID:      circuits.SD,
}

func opName(opID int) string {
	for name, id := range circuits.QueryOperators {
		if id == opID {
			return name
		}
	}
	return fmt.Sprintf("Operator<%d>", opID)
}

func queriesFromObjNonMerklized(ctx context.Context,
	w3cCred verifiable.W3CCredential, requestObj jsonObj,
	documentLoader ld.DocumentLoader, circuitID circuits.CircuitID,
	cacheDir string) ([]*circuits.Query, jsonObj, error) {

	var err error

	region := trace.StartRegion(ctx, "queryFromObjNonMerklized")
	defer region.End()

	pr := processor.InitProcessorOptions(&processor.Processor{
		DocumentLoader: documentLoader,
		Parser:         json2.Parser{},
	})

	var queries = make([]*circuits.Query, circuits.LinkedMultiQueryLength)
	var queryIndex = 0
	credSubjObj, err := objByBath(requestObj, "query.credentialSubject")
	if errors.As(err, &errPathNotFound{}) {

		queries[0] = new(circuits.Query)

		if isV2Circuit(circuitID) {
			return nil, nil, errors.New(
				"credentialSubject field is not found in query")
		}
		queries[0].Operator = circuits.NOOP
		queries[0].Values = []*big.Int{}
		return queries, nil, nil
	} else if err != nil {
		return nil, nil, fmt.Errorf(
			"unable to extract credentialSubject field from query: %w", err)
	}

	contextURL, contextType, err := getQuerySchemaAndType(requestObj)
	if err != nil {
		return nil, nil, err
	}

	schema, err := pr.Load(ctx, contextURL)
	if err != nil {
		return nil, nil, err
	}

	var mz *merklize.Merklizer
	mz, err = wrapMerklizeWithRegion(ctx, w3cCred, documentLoader, cacheDir)
	if err != nil {
		return nil, nil, err
	}

	var vpEntries []objEntry
	fields := sortedKeys(credSubjObj)
	for _, field := range fields {
		var slotIndex int
		slotIndex, err = pr.GetFieldSlotIndex(field, contextType, schema)
		if err != nil {
			return nil, nil, err
		}

		var path merklize.Path
		path, err = buildQueryPath(ctx, contextURL, contextType, field,
			documentLoader)
		if err != nil {
			return nil, nil, err
		}

		var datatype string
		datatype, err = mz.JSONLDType(path)
		if err != nil {
			return nil, nil, err
		}

		ops, ok := credSubjObj[field].(jsonObj)
		if !ok {
			return nil, nil, fmt.Errorf(
				"for query field '%v' the operator object is of incorrect type: %T",
				field, credSubjObj[field])
		}

		if len(ops) == 0 {
			// handle selective disclosure

			if queryIndex >= circuits.LinkedMultiQueryLength {
				return nil, nil, errors.New("too many queries")
			}

			query := circuits.Query{SlotIndex: slotIndex}

			var sdOp int
			sdOp, ok = sdOperator[circuitID]
			if !ok {
				return nil, nil, errSDCircuitNotSupported{circuitID}
			}

			switch sdOp {
			case circuits.SD:
				query.Operator = sdOp
				query.Values = []*big.Int{}
			case circuits.EQ:
				var mzValue merklize.Value
				var p *merkletree.Proof
				p, mzValue, err = mz.Proof(ctx, path)
				if err != nil {
					return nil, nil, err
				}
				if !p.Existence {
					return nil, nil, fmt.Errorf(
						"value not found in verifiable credential by path %v",
						fmtPath(path))
				}
				if mzValue == nil {
					// should not happen because of the existence check previously
					return nil, nil, fmt.Errorf(
						"[assertion] merklized value is nil for path %v",
						fmtPath(path))
				}

				var valueEntry *big.Int
				valueEntry, err = mzValue.MtEntry()
				if err != nil {
					return nil, nil, err
				}
				query.Operator = sdOp
				query.Values = []*big.Int{valueEntry}
			default:
				return nil, nil, errSDOperatorNotSupported{sdOp}
			}

			queries[queryIndex] = &query
			queryIndex++

			vpEntry := objEntry{key: field}
			vpEntry.value, err = mz.RawValue(path)
			if err != nil {
				return nil, nil, err
			}
			vpEntries = append(vpEntries, vpEntry)

		} else {
			sortedOps := sortedKeys(ops)
			for _, op := range sortedOps {
				val := ops[op]

				if queryIndex >= circuits.LinkedMultiQueryLength {
					return nil, nil, errors.New("too many queries")
				}

				query := circuits.Query{SlotIndex: slotIndex}
				query.Operator, query.Values, err = unpackOperatorWithArgs(op,
					val, datatype, mz.Hasher())
				if err != nil {
					return nil, nil, err
				}

				queries[queryIndex] = &query
				queryIndex++
			}
		}

	}

	var verifiablePresentation jsonObj
	if len(vpEntries) > 0 {
		verifiablePresentation, err = fmtVerifiablePresentation(contextURL,
			contextType, vpEntries...)
		if err != nil {
			return nil, nil, err
		}
	}

	return queries, verifiablePresentation, nil
}

func getQuerySchemaAndType(requestObj jsonObj) (string, string, error) {
	typeName, err := stringByPath(requestObj, "query.type")
	if err != nil {
		return "", "", err
	}
	schemaURL, err := stringByPath(requestObj, "query.context")
	if err != nil {
		return "", "", err
	}
	return schemaURL, typeName, nil
}

func getCircuitID(requestObj jsonObj) (circuits.CircuitID, error) {
	circuitID, err := stringByPath(requestObj, "circuitId")
	if err != nil {
		return "", err
	}
	return circuits.CircuitID(circuitID), nil
}

const iriCredentialSubject = "https://www.w3.org/2018/credentials#credentialSubject"

func mkValueProof(ctx context.Context, mz *merklize.Merklizer,
	path merklize.Path) (*circuits.ValueProof, error) {

	existenceProof, mzValue, err := mz.Proof(ctx, path)
	if err != nil {
		return nil, err
	}

	var valueEntry *big.Int
	if existenceProof.Existence {
		valueEntry, err = mzValue.MtEntry()
		if err != nil {
			return nil, err
		}
	} else {
		valueEntry = big.NewInt(0)
	}

	var pathEntry *big.Int
	pathEntry, err = path.MtEntry()
	if err != nil {
		return nil, err
	}

	return &circuits.ValueProof{
		Path:  pathEntry,
		Value: valueEntry,
		MTP:   existenceProof,
	}, nil
}

func mkEqQuery(ctx context.Context, mz *merklize.Merklizer,
	path merklize.Path) (circuits.Query, error) {

	valueProof, err := mkValueProof(ctx, mz, path)
	if err != nil {
		return circuits.Query{}, err
	}

	return circuits.Query{
		Operator:   circuits.EQ,
		Values:     []*big.Int{valueProof.Value},
		ValueProof: valueProof,
	}, nil
}

type errSDCircuitNotSupported struct {
	circuitID circuits.CircuitID
}

func (e errSDCircuitNotSupported) Error() string {
	return fmt.Sprintf("selective disclosure is not supported by circuit %v",
		e.circuitID)
}

type errSDOperatorNotSupported struct {
	operator int
}

func (e errSDOperatorNotSupported) Error() string {
	return fmt.Sprintf("operator %v is not supported for selective disclosure",
		opName(e.operator))
}

func sortedKeys(m jsonObj) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func queriesFromObjMerklized(ctx context.Context,
	w3cCred verifiable.W3CCredential, requestObj jsonObj,
	documentLoader ld.DocumentLoader, circuitID circuits.CircuitID,
	_ *core.Claim, cacheDir string) ([]*circuits.Query, jsonObj, error) {

	region := trace.StartRegion(ctx, "queryFromObjMerklized")
	defer region.End()

	mz, err := wrapMerklizeWithRegion(ctx, w3cCred, documentLoader, cacheDir)
	if err != nil {
		return nil, nil, err
	}

	// TODO uncomment this on tests fixes
	//mzRoot, err := claim.GetMerklizedRoot()
	//if err != nil {
	//	return out, nil, err
	//}
	//if mzRoot.Cmp(mz.Root().BigInt()) != 0 {
	//	return out, nil, fmt.Errorf(
	//		"claim's merklized root does not match calculated merklized "+
	//			"credential root. Claim's merklized root: %v, "+
	//			"credential merklized croot: %v",
	//		mzRoot.String(), mz.Root().BigInt().String())
	//}

	var contextURL, contextType string
	contextURL, contextType, err = getQuerySchemaAndType(requestObj)
	if err != nil {
		return nil, nil, err
	}

	var queries = make([]*circuits.Query, circuits.LinkedMultiQueryLength)
	var queryIndex = 0
	var credSubjObj jsonObj
	credSubjObj, err = objByBath(requestObj, "query.credentialSubject")
	if errors.As(err, &errPathNotFound{}) {

		queries[0] = new(circuits.Query)

		if circuitID == circuits.AtomicQueryV3CircuitID ||
			circuitID == circuits.AtomicQueryV3OnChainCircuitID ||
			circuitID == circuits.LinkedMultiQuery10CircuitID {
			queries[0].Operator = circuits.NOOP
			queries[0].Values = []*big.Int{}
		} else {
			var path merklize.Path
			path, err = merklize.NewPath(iriCredentialSubject)
			if err != nil {
				return nil, nil, err
			}
			*queries[0], err = mkEqQuery(ctx, mz, path)
			if err != nil {
				return nil, nil, err
			}
		}

		return queries, nil, nil
	} else if err != nil {
		return nil, nil,
			fmt.Errorf("unable to extract field from query: %w", err)
	}

	var vpEntries []objEntry
	fields := sortedKeys(credSubjObj)
	for _, field := range fields {
		ops, ok := credSubjObj[field].(jsonObj)
		if !ok {
			return nil, nil, fmt.Errorf(
				"for query field '%v' the operator object is of incorrect type: %T",
				field, credSubjObj[field])

		}

		var path merklize.Path
		path, err = buildQueryPath(ctx, contextURL, contextType, field,
			documentLoader)
		if err != nil {
			return nil, nil, err
		}

		var valueProof *circuits.ValueProof
		valueProof, err = mkValueProof(ctx, mz, path)
		if err != nil {
			return nil, nil, err
		}

		if len(ops) == 0 {

			// Handle selective disclosure

			if queryIndex >= circuits.LinkedMultiQueryLength {
				return nil, nil, errors.New("too many queries")
			}

			var query = circuits.Query{ValueProof: valueProof}
			var sdOp int
			sdOp, ok = sdOperator[circuitID]
			if !ok {
				return nil, nil, errSDCircuitNotSupported{circuitID}
			}

			switch sdOp {
			case circuits.SD:
				query.Operator = circuits.SD
				query.Values = []*big.Int{}
			case circuits.EQ:
				query.Operator = circuits.EQ
				query.Values = []*big.Int{query.ValueProof.Value}
			default:
				return nil, nil, errSDOperatorNotSupported{sdOp}
			}

			queries[queryIndex] = &query
			queryIndex++

			vpEntry := objEntry{key: field}
			vpEntry.value, err = mz.RawValue(path)
			if err != nil {
				return nil, nil, err
			}
			vpEntries = append(vpEntries, vpEntry)

		} else {

			sortedOps := sortedKeys(ops)
			for _, op := range sortedOps {
				val := ops[op]

				var fieldDatatype string
				if valueProof.MTP.Existence {
					fieldDatatype, err = mz.JSONLDType(path)
				} else {
					fieldDatatype, err = datatypeFromContext(contextURL,
						contextType, field, documentLoader, mz.Hasher())
				}
				if err != nil {
					return nil, nil, err
				}

				var query = circuits.Query{ValueProof: valueProof}
				query.Operator, query.Values, err = unpackOperatorWithArgs(op,
					val, fieldDatatype, mz.Hasher())
				if err != nil {
					return nil, nil, err
				}

				if queryIndex >= circuits.LinkedMultiQueryLength {
					return nil, nil, errors.New("too many queries")
				}
				queries[queryIndex] = &query
				queryIndex++
			}
		}
	}

	var verifiablePresentation jsonObj
	if len(vpEntries) > 0 {
		verifiablePresentation, err = fmtVerifiablePresentation(contextURL,
			contextType, vpEntries...)
		if err != nil {
			return nil, nil, err
		}
	}

	return queries, verifiablePresentation, nil
}

// Return int operator value by its name and arguments as big.Ints array.
func unpackOperatorWithArgs(opStr string, opValue any,
	datatype string, hasher merklize.Hasher) (int, []*big.Int, error) {

	op, ok := circuits.QueryOperators[opStr]
	if !ok {
		return 0, nil, errors.New("unknown operator")
	}

	if op == circuits.EXISTS {
		var existsVal bool
		existsVal, ok = opValue.(bool)
		if !ok {
			return 0, nil, errors.New("$exists operator value is not a boolean")
		}
		if existsVal {
			return op, []*big.Int{big.NewInt(1)}, nil
		}
		return op, []*big.Int{big.NewInt(0)}, nil
	}

	hashFn := func(val any) (*big.Int, error) {
		if hasher == nil {
			return merklize.HashValue(datatype, val)
		} else {
			return merklize.HashValueWithHasher(hasher, datatype, val)
		}
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
	skipClaimRevocationCheck bool,
	claimProcessFn func(claim *core.Claim)) (circuits.ClaimWithMTPProof, error) {

	region := trace.StartRegion(ctx, "claimWithMtpProofFromObj")
	defer region.End()

	var out circuits.ClaimWithMTPProof
	var err error
	var proofI verifiable.CredentialProof
	var issuerDID *w3c.DID

	if proofI = findProofByType(w3cCred,
		verifiable.Iden3SparseMerkleTreeProofType); proofI != nil {

		proof, ok := proofI.(*verifiable.Iden3SparseMerkleTreeProof)
		if !ok {
			return out, errors.New("proof is not a sparse merkle proof")
		}
		issuerDID, err = w3c.ParseDID(proof.IssuerData.ID)
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
		issuerDID, err = w3c.ParseDID(proof.IssuerData.ID)
		if err != nil {
			return out, err
		}
		out.IncProof.Proof = proof.MTP
		out.IncProof.TreeState, err = circuitsTreeStateFromSchemaState(proof.IssuerData.State)
		if err != nil {
			return out, err
		}
	} else {
		return out, errProofNotFound(verifiable.Iden3SparseMerkleTreeProofType)
	}

	userDID, err := userDIDFromCred(w3cCred)
	if err != nil {
		return out, err
	}

	issuerID, err := core.IDFromDID(*issuerDID)
	if err != nil {
		return out, err
	}
	out.IssuerID = &issuerID

	out.Claim, err = proofI.GetCoreClaim()
	if err != nil {
		return out, err
	}

	if claimProcessFn != nil {
		claimProcessFn(out.Claim)
	}

	credStatus, ok := w3cCred.CredentialStatus.(jsonObj)
	if !ok {
		return out, errors.New("not a json object")
	}

	out.NonRevProof, err = buildAndValidateCredentialStatus(ctx, cfg,
		credStatus, issuerDID, userDID, skipClaimRevocationCheck)
	if err != nil {
		return out, ErrCredentialStatus{
			err:   err,
			owner: CredentialStatusOwnerUser,
		}
	}

	return out, nil
}

func v3ProofFromMTP(
	p circuits.ClaimWithMTPProof) circuits.ClaimWithSigAndMTPProof {
	return circuits.ClaimWithSigAndMTPProof{
		IssuerID:    p.IssuerID,
		Claim:       p.Claim,
		NonRevProof: p.NonRevProof,
		IncProof:    &p.IncProof,
	}
}

func v3ProofFromSig(p circuits.ClaimWithSigProof) circuits.ClaimWithSigAndMTPProof {
	return circuits.ClaimWithSigAndMTPProof{
		IssuerID:       p.IssuerID,
		Claim:          p.Claim,
		NonRevProof:    p.NonRevProof,
		SignatureProof: &p.SignatureProof,
	}

}

func claimWithSigAndMtpProofFromObj(ctx context.Context, cfg EnvConfig,
	w3cCred verifiable.W3CCredential, skipClaimRevocationCheck bool,
	proofType circuits.ProofType) (circuits.ClaimWithSigAndMTPProof, circuits.ProofType, error) {

	switch proofType {
	case circuits.Iden3SparseMerkleTreeProofType:
		claimWithMtpProof, err := claimWithMtpProofFromObj(ctx, cfg, w3cCred,
			skipClaimRevocationCheck, nil)
		if err != nil {
			return circuits.ClaimWithSigAndMTPProof{}, proofType, err
		}
		return v3ProofFromMTP(claimWithMtpProof), proofType, nil
	case circuits.BJJSignatureProofType:
		claimWithSigProof, err := claimWithSigProofFromObj(ctx, cfg, w3cCred,
			skipClaimRevocationCheck)
		if err != nil {
			return circuits.ClaimWithSigAndMTPProof{}, proofType, err
		}
		return v3ProofFromSig(claimWithSigProof), proofType, nil
	case "":
		claimWithMtpProof, err := claimWithMtpProofFromObj(ctx, cfg, w3cCred,
			skipClaimRevocationCheck, nil)
		var tErr errProofNotFound
		switch {
		case errors.As(err, &tErr):
			claimWithSigProof, err := claimWithSigProofFromObj(ctx, cfg,
				w3cCred, skipClaimRevocationCheck)
			if err != nil {
				return circuits.ClaimWithSigAndMTPProof{}, proofType, err
			}
			return v3ProofFromSig(claimWithSigProof),
				circuits.BJJSignatureProofType, nil
		case err != nil:
			return circuits.ClaimWithSigAndMTPProof{}, proofType, err
		}

		return v3ProofFromMTP(claimWithMtpProof),
			circuits.Iden3SparseMerkleTreeProofType, nil
	default:
		return circuits.ClaimWithSigAndMTPProof{}, proofType,
			fmt.Errorf("unknown proofType: %v", proofType)
	}
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

func credStatusFromJsonObj(obj jsonObj) (verifiable.CredentialStatus, error) {
	var typedCredentialStatus verifiable.CredentialStatus
	err := remarshalObj(&typedCredentialStatus, obj)
	return typedCredentialStatus, err
}

// marshal/unmarshal object from one type to ther
func remarshalObj(dst, src any) error {
	objBytes, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(objBytes, dst)
}

type ChainConfig struct {
	RPCUrl            string
	StateContractAddr common.Address
}

func (cc ChainConfig) validate() error {
	if cc.RPCUrl == "" {
		return errors.New("ethereum url is empty")
	}

	if cc.StateContractAddr == (common.Address{}) {
		return errors.New("contract address is empty")
	}

	return nil
}

type PerChainConfig map[core.ChainID]ChainConfig

func (p *PerChainConfig) UnmarshalJSON(bytes []byte) error {
	if (*p) == nil {
		*p = make(PerChainConfig)
	}
	var o map[string]ChainConfig
	err := json.Unmarshal(bytes, &o)
	if err != nil {
		return err
	}
	for k, v := range o {
		var chainID core.ChainID
		chainID, err = newChainIDFromString(k)
		if err != nil {
			return err
		}
		(*p)[chainID] = v
	}
	return nil
}

func newChainIDFromString(in string) (core.ChainID, error) {
	radix := 10
	if strings.HasPrefix(in, "0x") || strings.HasPrefix(in, "0X") {
		radix = 16
		in = in[2:]
	}

	var chainID core.ChainID
	assertUnderlineTypeInt32(chainID)
	i, err := strconv.ParseInt(in, radix, 32)
	if err != nil {
		return 0, fmt.Errorf("can't parse ChainID type: %w", err)
	}
	return core.ChainID(i), nil
}

func merklizeCred(ctx context.Context, w3cCred verifiable.W3CCredential,
	documentLoader ld.DocumentLoader, ignoreCacheErrors bool,
	cacheDir string) (*merklize.Merklizer, error) {

	w3cCred.Proof = nil
	credentialBytes, err := json.Marshal(w3cCred)
	if err != nil {
		return nil, err
	}

	cacheKey := sha256.Sum256(credentialBytes)

	db, cleanup, err := getCacheDB(cacheDir)
	if err != nil {
		if !ignoreCacheErrors {
			return nil, err
		}
		slog.ErrorContext(ctx, "failed to get cache db", "err", err)
		db = nil
	} else {
		defer cleanup()
	}

	var mz *merklize.Merklizer
	var storage *inMemoryStorage

	if db != nil {
		mz, storage, err = getMzCache(ctx, db, cacheKey[:], documentLoader)
		if err != nil {
			if !ignoreCacheErrors {
				return nil, err
			}
			slog.ErrorContext(ctx, "failed to read value from cache db",
				"err", err)
			mz = nil
			storage = nil
		}
	}

	if mz == nil || storage == nil {
		slog.Debug("merklizeCred: cache miss")
		storage = newInMemoryStorage()

		var mt *merkletree.MerkleTree
		mt, err = merkletree.NewMerkleTree(ctx, storage, mtLevels)
		if err != nil {
			return nil, err
		}

		warmUpSchemaLoader(w3cCred.Context, documentLoader)

		mz, err = merklize.MerklizeJSONLD(ctx, bytes.NewReader(credentialBytes),
			merklize.WithDocumentLoader(documentLoader),
			merklize.WithMerkleTree(merklize.MerkleTreeSQLAdapter(mt)))
		if err != nil {
			return nil, err
		}

		if db != nil {
			err = saveMzCache(db, cacheKey[:], mz, storage)
			if err != nil {
				if !ignoreCacheErrors {
					return nil, err
				}
				slog.ErrorContext(ctx, "failed to save to the cache db",
					"err", err)
			}
		}
	} else {
		slog.Debug("merklizeCred: cache hit")
	}

	return mz, nil
}

func mzCacheKey(vcChecksum []byte) []byte {
	return appendSuffix("_mz", vcChecksum)
}

func storageCacheKey(vcChecksum []byte) []byte {
	return appendSuffix("_mt", vcChecksum)
}

func appendSuffix(suffix string, val []byte) []byte {
	newVal := make([]byte, len(val)+len(suffix))
	copy(newVal, val)
	copy(newVal[len(val):], suffix)
	return newVal
}

func saveMzCache(db *badger.DB, vcChecksum []byte, mz *merklize.Merklizer,
	storage *inMemoryStorage) error {

	expireAt := time.Now().Add(30 * 24 * time.Hour).Unix()

	var storageEntry = badger.Entry{
		Key:       storageCacheKey(vcChecksum),
		ExpiresAt: uint64(expireAt)}
	var mzEntry = badger.Entry{
		Key:       mzCacheKey(vcChecksum),
		ExpiresAt: uint64(expireAt)}

	var err error
	storageEntry.Value, err = storage.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal storage: %w", err)
	}

	mzEntry.Value, err = mz.MarshalBinary()
	if err != nil {
		return fmt.Errorf("failed to marshal merklizer: %w", err)
	}

	err = db.Update(func(txn *badger.Txn) error {
		if err := txn.SetEntry(&storageEntry); err != nil {
			return err
		}
		return txn.SetEntry(&mzEntry)
	})
	if err != nil {
		return fmt.Errorf("failed to save value to cache db: %w", err)
	}
	return nil
}

//func logWhatWasPutInCache(msg string, key []byte, value []byte) {
//	valueHex := hex.EncodeToString(value)
//	checksum := md5.Sum(value)
//	checksumHex := hex.EncodeToString(checksum[:])
//	keyHex := hex.EncodeToString(key)
//	slog.Debug(msg, "key", keyHex, "len", len(value),
//		"md5", checksumHex, "value", valueHex)
//}

func getMzCache(ctx context.Context, db *badger.DB, vcChecksum []byte,
	documentLoader ld.DocumentLoader) (*merklize.Merklizer, *inMemoryStorage,
	error) {

	var mz *merklize.Merklizer
	var storage *inMemoryStorage

	err := db.View(func(txn *badger.Txn) error {
		mtKey := storageCacheKey(vcChecksum)
		v, err := txn.Get(mtKey)
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		} else if err != nil {
			return err
		}

		storage = newInMemoryStorage()
		err = v.Value(func(val []byte) error {
			err = storage.UnmarshalBinary(val)
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}

		mzKey := mzCacheKey(vcChecksum)
		v, err = txn.Get(mzKey)
		if errors.Is(err, badger.ErrKeyNotFound) {
			return errors.New("merklized data not found in cache db")
		} else if err != nil {
			return err
		}

		var mt *merkletree.MerkleTree
		mt, err = merkletree.NewMerkleTree(ctx, storage, mtLevels)
		if err != nil {
			return err
		}

		return v.Value(func(val []byte) error {
			mz, err = merklize.MerklizerFromBytes(val,
				merklize.WithDocumentLoader(documentLoader),
				merklize.WithMerkleTree(merklize.MerkleTreeSQLAdapter(mt)))
			return err
		})
	})

	return mz, storage, err
}

func warmUpSchemaLoader(schemaURLs []string, docLoader ld.DocumentLoader) {
	var wg sync.WaitGroup
	start := time.Now()
	for _, schemaURL := range schemaURLs {
		wg.Add(1)
		go func(schemaURL string) {
			defer wg.Done()
			_, _ = docLoader.LoadDocument(schemaURL)
		}(schemaURL)
	}
	wg.Wait()
	slog.Debug("pre download schemas",
		"time", time.Since(start),
		"docsNum", len(schemaURLs))
}

func PreCacheVC(ctx context.Context, cfg EnvConfig, in []byte) error {
	var obj struct {
		VerifiableCredentials json.RawMessage `json:"verifiableCredentials"`
	}
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return err
	}

	var w3cCred verifiable.W3CCredential
	err = json.Unmarshal(obj.VerifiableCredentials, &w3cCred)
	if err != nil {
		return err
	}

	_, err = merklizeCred(ctx, w3cCred, cfg.documentLoader(), false,
		cfg.CacheDir)
	return err
}

func fmtPath(path merklize.Path) string {
	var parts []string
	for _, p := range path.Parts() {
		parts = append(parts, fmt.Sprintf("%v", p))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

type GenesysIDResponse struct {
	DID     string `json:"did"`
	ID      string `json:"id"`
	IDAsInt string `json:"idAsInt"`
}

func NewGenesysID(ctx context.Context, cfg EnvConfig,
	in []byte) (GenesysIDResponse, error) {

	var req struct {
		ClaimsTreeRoot *JsonFieldIntStr `json:"claimsTreeRoot"`
		Blockchain     *core.Blockchain `json:"blockchain"`
		Network        *core.NetworkID  `json:"network"`
		Method         *core.DIDMethod  `json:"method"`
	}

	if in == nil {
		return GenesysIDResponse{}, errors.New("request is empty")
	}

	err := json.Unmarshal(in, &req)
	if err != nil {
		return GenesysIDResponse{},
			fmt.Errorf("failed to unmarshal request: %w", err)
	}

	if req.ClaimsTreeRoot == nil {
		return GenesysIDResponse{},
			errors.New("claims tree root is not set in the request")
	}

	if req.Blockchain == nil {
		return GenesysIDResponse{},
			errors.New("blockchain is not set in the request")
	}

	if req.Network == nil {
		return GenesysIDResponse{},
			errors.New("network is not set in the request")
	}

	if req.Method == nil {
		// for backward compatibility, if method is not set, use polygon
		var m = core.DIDMethodPolygonID
		req.Method = &m
	}

	state, err := merkletree.HashElems(req.ClaimsTreeRoot.Int(),
		merkletree.HashZero.BigInt(), merkletree.HashZero.BigInt())
	if err != nil {
		return GenesysIDResponse{},
			fmt.Errorf("failed to calculate state: %w", err)
	}

	typ, err := core.BuildDIDType(*req.Method, *req.Blockchain,
		*req.Network)
	if err != nil {
		return GenesysIDResponse{},
			fmt.Errorf("failed to build DID type: %w", err)
	}

	coreID, err := core.NewIDFromIdenState(typ, state.BigInt())
	if err != nil {
		return GenesysIDResponse{},
			fmt.Errorf("failed to create ID: %w", err)
	}

	did, err := core.ParseDIDFromID(*coreID)
	if err != nil {
		return GenesysIDResponse{},
			fmt.Errorf("failed to make DID from ID: %w", err)
	}

	return GenesysIDResponse{
			DID:     did.String(),
			ID:      coreID.String(),
			IDAsInt: coreID.BigInt().String(),
		},
		nil
}

func NewGenesysIDFromEth(ctx context.Context, cfg EnvConfig,
	in []byte) (GenesysIDResponse, error) {

	var req struct {
		EthAddr    *common.Address  `json:"ethAddress"`
		Blockchain *core.Blockchain `json:"blockchain"`
		Network    *core.NetworkID  `json:"network"`
		Method     *core.DIDMethod  `json:"method"`
	}

	if in == nil {
		return GenesysIDResponse{}, errors.New("request is empty")
	}

	err := json.Unmarshal(in, &req)
	if err != nil {
		return GenesysIDResponse{},
			fmt.Errorf("failed to unmarshal request: %w", err)
	}

	if req.EthAddr == nil {
		return GenesysIDResponse{},
			errors.New("ethereum address is not set in the request")
	}

	if req.Blockchain == nil {
		return GenesysIDResponse{},
			errors.New("blockchain is not set in the request")
	}

	if req.Network == nil {
		return GenesysIDResponse{},
			errors.New("network is not set in the request")
	}

	if req.Method == nil {
		// for backward compatibility, if method is not set, use polygon
		var m = core.DIDMethodPolygonID
		req.Method = &m
	}

	typ, err := core.BuildDIDType(*req.Method, *req.Blockchain,
		*req.Network)
	if err != nil {
		return GenesysIDResponse{},
			fmt.Errorf("failed to build DID type: %w", err)
	}

	genesis := core.GenesisFromEthAddress(*req.EthAddr)
	coreID := core.NewID(typ, genesis)

	did, err := core.ParseDIDFromID(coreID)
	if err != nil {
		return GenesysIDResponse{},
			fmt.Errorf("failed to make DID from ID: %w", err)
	}

	return GenesysIDResponse{
			DID:     did.String(),
			ID:      coreID.String(),
			IDAsInt: coreID.BigInt().String(),
		},
		nil
}

type DescribeIDResponse struct {
	DID     string `json:"did"`
	ID      string `json:"id"`
	IDAsInt string `json:"idAsInt"`
}

func DescribeID(ctx context.Context, cfg EnvConfig,
	in []byte) (DescribeIDResponse, error) {

	var req struct {
		ID      *core.ID         `json:"id"`
		IDAsInt *JsonFieldIntStr `json:"idAsInt"`
	}

	if in == nil {
		return DescribeIDResponse{}, errors.New("request is empty")
	}

	err := json.Unmarshal(in, &req)
	if err != nil {
		return DescribeIDResponse{},
			fmt.Errorf("failed to unmarshal request: %w", err)
	}

	var id *core.ID
	if req.ID != nil {
		id = req.ID
	}

	if req.IDAsInt != nil {
		newID, err := core.IDFromInt(req.IDAsInt.Int())
		if err != nil {
			return DescribeIDResponse{},
				fmt.Errorf("failed to create ID from int: %w", err)
		}
		if id == nil {
			id = &newID
		} else if !id.Equal(&newID) {
			return DescribeIDResponse{},
				errors.New("id and idAsInt are different")
		}
	}

	if id == nil {
		return DescribeIDResponse{}, errors.New("id is not set in the request")
	}

	did, err := core.ParseDIDFromID(*id)
	if err != nil {
		return DescribeIDResponse{},
			fmt.Errorf("failed to make DID from ID: %w", err)
	}

	return DescribeIDResponse{
		DID:     did.String(),
		ID:      id.String(),
		IDAsInt: id.BigInt().String(),
	}, nil
}

func AnonAadhaarInputsFromJson(ctx context.Context, cfg EnvConfig,
	in []byte) (AtomicQueryInputsResponse, error) {

	var out AtomicQueryInputsResponse
	var inputs anonAadhaarV1Inputs
	err := json.Unmarshal(in, &inputs)
	if err != nil {
		return out, err
	}

	out.Inputs = inputs.asAnonAadhaarV1Inputs()
	return out, nil
}

func PassportInputsFromJson(ctx context.Context, cfg EnvConfig,
	in []byte) (AtomicQueryInputsResponse, error) {

	var inputs externalpassport.PassportV1Inputs
	err := json.Unmarshal(in, &inputs)
	if err != nil {
		return AtomicQueryInputsResponse{}, err
	}

	return AtomicQueryInputsResponse{
		Inputs: &inputs,
	}, nil
}

func W3cCredentialsFromAnonAadhaarInputsJson(ctx context.Context, cfg EnvConfig,
	in []byte) (verifiable.W3CCredential, error) {

	var inputs anonAadhaarV1Inputs
	err := json.Unmarshal(in, &inputs)
	if err != nil {
		return verifiable.W3CCredential{}, err
	}

	w3cCred, err := inputs.asAnonAadhaarV1Inputs().W3CCredential()
	if err != nil {
		return verifiable.W3CCredential{}, err
	}

	return *w3cCred, nil
}

func W3cCredentialsFromPassportInputsJson(ctx context.Context, cfg EnvConfig,
	in []byte) (verifiable.W3CCredential, error) {
	var inputs externalpassport.PassportV1Inputs
	err := json.Unmarshal(in, &inputs)
	if err != nil {
		return verifiable.W3CCredential{}, err
	}

	w3cCred, err := inputs.W3CCredential()
	if err != nil {
		return verifiable.W3CCredential{}, err
	}

	return *w3cCred, nil
}

type CoreClaimResponse struct {
	CoreClaim          *core.Claim `json:"coreClaim"`
	CoreClaimHex       string      `json:"coreClaimHex"`
	CoreClaimIndexHash *JsonBigInt `json:"coreClaimHIndex"`
	CoreClaimValueHash *JsonBigInt `json:"coreClaimHValue"`
}

func W3CCredentialToCoreClaim(ctx context.Context, cfg EnvConfig, in []byte) (CoreClaimResponse, error) {
	var req struct {
		W3CCredential    *verifiable.W3CCredential    `json:"w3cCredential"`
		CoreClaimOptions *verifiable.CoreClaimOptions `json:"coreClaimOptions"`
	}
	err := json.Unmarshal(in, &req)
	if err != nil {
		return CoreClaimResponse{}, err
	}
	if req.W3CCredential == nil {
		return CoreClaimResponse{},
			errors.New("w3cCredential is not set in the request")
	}

	if req.CoreClaimOptions == nil {
		req.CoreClaimOptions = &verifiable.CoreClaimOptions{
			RevNonce:              0,
			Version:               0,
			SubjectPosition:       verifiable.CredentialSubjectPositionIndex,
			MerklizedRootPosition: verifiable.CredentialMerklizedRootPositionNone,
			Updatable:             false,
			MerklizerOpts:         nil,
		}
	}

	req.CoreClaimOptions.MerklizerOpts = append(
		req.CoreClaimOptions.MerklizerOpts,
		merklize.WithDocumentLoader(cfg.documentLoader()))

	var resp CoreClaimResponse

	resp.CoreClaim, err = req.W3CCredential.ToCoreClaim(ctx,
		req.CoreClaimOptions)
	if err != nil {
		return CoreClaimResponse{}, err
	}

	ih, vh, err := resp.CoreClaim.HiHv()
	if err != nil {
		return CoreClaimResponse{}, err
	}
	resp.CoreClaimIndexHash = NewJsonBigInt(ih)
	resp.CoreClaimValueHash = NewJsonBigInt(vh)

	resp.CoreClaimHex, err = resp.CoreClaim.Hex()
	if err != nil {
		return CoreClaimResponse{}, err
	}

	return resp, nil
}

func repackDIDtoID(in []byte) ([]byte, error) {
	var obj map[string]any
	err := json.Unmarshal(in, &obj)
	if err != nil {
		return nil, err
	}

	didI, ok := obj["genesisDID"]
	if !ok {
		return nil, errors.New("no genesisDID field found")
	}

	didS, ok := didI.(string)
	if !ok {
		return nil, errors.New("genesisDID is not a string")
	}

	did, err := w3c.ParseDID(didS)
	if err != nil {
		return nil, fmt.Errorf("failed to parse genesisDID: %w", err)
	}

	id, err := core.IDFromDID(*did)
	if err != nil {
		return nil, fmt.Errorf("failed to get ID from genesisDID: %w", err)
	}
	obj["genesisID"] = id.String()

	out, err := json.Marshal(obj)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal data: %w", err)
	}

	return out, nil
}

func AuthInputsFromJson[T circuits.InputsMarshaller](in []byte,
	inputsCfg circuits.BaseConfig) (AtomicQueryInputsResponse, error) {

	var out AtomicQueryInputsResponse

	inputsData, err := repackDIDtoID(in)
	if err != nil {
		return out, fmt.Errorf("failed convert genesisDID to genesisID: %w",
			err)
	}

	var inputs T
	err = json.Unmarshal(inputsData, &inputs)
	if err != nil {
		return out, fmt.Errorf("failed to unmarshal auth inputs: %w", err)
	}

	var signature *babyjub.Signature
	var challenge *big.Int
	var authClaim *core.Claim

	switch v := any(&inputs).(type) {
	case *circuits.AuthV2Inputs:
		v.BaseConfig = inputsCfg
		signature = v.Signature
		challenge = v.Challenge
		authClaim = v.AuthClaim
	case *circuits.AuthV3Inputs:
		out.CircuitID, err = circuits.AdjustInputsForMinCircuit(v)
		if err != nil {
			return out, fmt.Errorf("failed to adjust inputs for min circuit: %w", err)
		}
		signature = v.Signature
		challenge = v.Challenge
		authClaim = v.AuthClaim
	default:
		return out, fmt.Errorf("unsupported auth inputs type %T", v)
	}

	slots := authClaim.RawSlotsAsInts()
	pubKey := &babyjub.PublicKey{X: slots[2], Y: slots[3]}
	if !pubKey.VerifyPoseidon(challenge, signature) {
		return out, errors.New("invalid signature")
	}

	out.Inputs = inputs

	return out, nil
}
