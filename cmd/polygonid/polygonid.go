package main

/*
#include <stdlib.h>
#include <string.h>

typedef enum
{
	PLGNSTATUSCODE_ERROR,
	PLGNSTATUSCODE_NIL_POINTER,
} PLGNStatusCode;

typedef struct _PLGNStatus
{
	PLGNStatusCode status;
	char *error_msg;
} PLGNStatus;
*/
import "C"

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"runtime"
	"runtime/trace"
	"strings"
	"time"
	"unsafe"

	c_polygonid "github.com/0xPolygonID/c-polygonid"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/utils"
	"github.com/iden3/go-merkletree-sql/v2"
)

var defaultTimeout = 30 * time.Second

type hexBytesStr []byte

func (h *hexBytesStr) UnmarshalJSON(bytes []byte) error {
	var s *string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}
	if s == nil {
		*h = nil
		return nil
	}

	decoded, err := hex.DecodeString(*s)
	if err != nil {
		return err
	}
	*h = append((*h)[:0], decoded...)

	return nil
}

type coreIDStr core.ID

func (id *coreIDStr) UnmarshalJSON(bytes []byte) error {
	var s *string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}
	if s == nil {
		*id = coreIDStr(core.ID{})
		return nil
	}

	coreID, err := core.IDFromString(*s)
	if err != nil {
		return err
	}

	*id = coreIDStr(coreID)
	return nil
}

func (id *coreIDStr) ID() core.ID {
	return core.ID(*id)
}

type jsonIntStr big.Int

func (i *jsonIntStr) UnmarshalJSON(bytes []byte) error {
	var s *string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}
	if s == nil {
		(*big.Int)(i).SetInt64(0)
		return nil
	}

	_, ok := (*big.Int)(i).SetString(*s, 10)
	if !ok {
		return fmt.Errorf("invalid Int string")
	}

	if !utils.CheckBigIntInField((*big.Int)(i)) {
		return fmt.Errorf("int is not in field")
	}

	return nil
}

func (i *jsonIntStr) Int() *big.Int {
	return (*big.Int)(i)
}

func maybeCreateStatus(status **C.PLGNStatus, code C.PLGNStatusCode,
	msgFmt string, msgParams ...interface{}) {

	if status == nil {
		return
	}

	s := (*C.PLGNStatus)(C.malloc(C.sizeof_PLGNStatus))
	if s == nil {
		return
	}

	if msgFmt != "" {
		msg := fmt.Sprintf(msgFmt, msgParams...)
		s.error_msg = C.CString(msg)
	} else {
		s.error_msg = nil
	}

	s.status = code

	*status = s
}

//export PLGNAuthV2InputsMarshal
func PLGNAuthV2InputsMarshal(jsonResponse **C.char, in *C.char,
	status **C.PLGNStatus) bool {

	_, cancel := logAPITime()
	defer cancel()

	if jsonResponse == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"jsonResponse pointer is nil")
		return false
	}

	var obj map[string]any
	err := json.Unmarshal([]byte(C.GoString(in)), &obj)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	didI, ok := obj["genesisDID"]
	if !ok {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"PLGNAuthV2InputsMarshal: No genesisDID field found")
		return false
	}

	didS, ok := didI.(string)
	if !ok {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"PLGNAuthV2InputsMarshal: No genesisDID field found")
		return false
	}

	did, err := w3c.ParseDID(didS)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"PLGNAuthV2InputsMarshal: DID parse error: %v", err)
		return false
	}

	id, err := core.IDFromDID(*did)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"PLGNAuthV2InputsMarshal: error getting ID from DID: %v", err)
		return false
	}
	obj["genesisID"] = id.String()

	authV2InputsData, err := json.Marshal(obj)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"PLGNAuthV2InputsMarshal: error marshal data %v", err)
		return false
	}

	var inputs circuits.AuthV2Inputs
	err = json.Unmarshal(authV2InputsData, &inputs)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"PLGNAuthV2InputsMarshal: inputs unmarshal error: %v", err)
		return false
	}

	circuitInputJSON, err := inputs.InputsMarshal()
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"PLGNAuthV2InputsMarshal: inputs marshal error: %v", err)
		return false
	}

	*jsonResponse = C.CString(string(circuitInputJSON))
	return true
}

// Deprecated: Use PLGNNewGenesisID instead. It supports environment
// configuration, giving the ability to register custom DID methods.
//
//export PLGNCalculateGenesisID
func PLGNCalculateGenesisID(jsonResponse **C.char, in *C.char,
	status **C.PLGNStatus) bool {

	ctx, cancel := logAPITime()
	defer cancel()

	if in == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"pointer to request is nil")
		return false
	}

	inStr := C.GoString(in)
	resp, err := c_polygonid.NewGenesysID(ctx, c_polygonid.EnvConfig{},
		[]byte(inStr))
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	respB, err := json.Marshal(resp)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	*jsonResponse = C.CString(string(respB))
	return true
}

//export PLGNNewGenesisID
func PLGNNewGenesisID(jsonResponse **C.char, in *C.char, cfg *C.char,
	status **C.PLGNStatus) bool {

	ctx, cancel := logAPITime()
	defer cancel()

	if in == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"pointer to request is nil")
		return false
	}

	envCfg, err := createEnvConfig(cfg)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	inStr := C.GoString(in)
	resp, err := c_polygonid.NewGenesysID(ctx, envCfg, []byte(inStr))
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	respB, err := json.Marshal(resp)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	*jsonResponse = C.CString(string(respB))
	return true
}

//export PLGNCreateClaim
func PLGNCreateClaim(jsonResponse **C.char, in *C.char,
	status **C.PLGNStatus) (ok bool) {

	_, cancel := logAPITime()
	defer cancel()

	req := struct {
		Schema             hexBytesStr `json:"schema"`
		FlagUpdatable      *bool       `json:"flagUpdatable"`
		Version            *uint32     `json:"version"`
		IndexMerklizedRoot *jsonIntStr `json:"indexMerklizedRoot"`
		ValueMerklizedRoot *jsonIntStr `json:"valueMerklizedRoot"`
		IndexID            *coreIDStr  `json:"indexID"`
		ValueID            *coreIDStr  `json:"valueID"`
		Nonce              *jsonIntStr `json:"nonce"`
		ExpirationDate     *time.Time  `json:"expirationDate"`
		IndexSlotA         *jsonIntStr `json:"indexSlotA"`
		IndexSlotB         *jsonIntStr `json:"indexSlotB"`
		ValueSlotA         *jsonIntStr `json:"valueSlotA"`
		ValueSlotB         *jsonIntStr `json:"valueSlotB"`
	}{}

	if in == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"pointer to request is nil")
		return false
	}

	err := json.Unmarshal([]byte(C.GoString(in)), &req)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	var schema core.SchemaHash
	if len(req.Schema) != len(schema) {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"invalid schema length")
		return false
	}

	copy(schema[:], req.Schema)

	c, err := core.NewClaim(schema)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	if req.FlagUpdatable != nil {
		c.SetFlagUpdatable(*req.FlagUpdatable)
	}

	if req.Version != nil {
		c.SetVersion(*req.Version)
	}

	if req.IndexMerklizedRoot != nil {
		err = c.SetIndexMerklizedRoot(req.IndexMerklizedRoot.Int())
		if err != nil {
			maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
			return false
		}
	}

	if req.ValueMerklizedRoot != nil {
		err = c.SetValueMerklizedRoot(req.ValueMerklizedRoot.Int())
		if err != nil {
			maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
			return false
		}
	}

	if req.IndexID != nil {
		c.SetIndexID(req.IndexID.ID())
	}

	if req.ValueID != nil {
		c.SetValueID(req.ValueID.ID())
	}

	if req.Nonce != nil {
		if !req.Nonce.Int().IsUint64() {
			maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
				"nonce is too big")
			return false
		}
		c.SetRevocationNonce(req.Nonce.Int().Uint64())
	}

	if req.ExpirationDate != nil {
		c.SetExpirationDate(*req.ExpirationDate)
	}

	if req.IndexSlotA != nil || req.IndexSlotB != nil {
		var slotA = big.NewInt(0)
		var slotB = big.NewInt(0)
		if req.IndexSlotA != nil {
			slotA = req.IndexSlotA.Int()
		}
		if req.IndexSlotB != nil {
			slotB = req.IndexSlotB.Int()
		}
		err = c.SetIndexDataInts(slotA, slotB)
		if err != nil {
			maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
			return false
		}
	}

	if req.ValueSlotA != nil || req.ValueSlotB != nil {
		var slotA = big.NewInt(0)
		var slotB = big.NewInt(0)
		if req.ValueSlotA != nil {
			slotA = req.ValueSlotA.Int()
		}
		if req.ValueSlotB != nil {
			slotB = req.ValueSlotB.Int()
		}
		err = c.SetValueDataInts(slotA, slotB)
		if err != nil {
			maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
			return false
		}
	}

	respB, err := json.Marshal(c)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	*jsonResponse = C.CString(string(respB))
	return true
}

// PLGNIDToInt returns the ID as a big int string
// Input should be a valid JSON object: string enclosed by double quotes.
// Output is a valid JSON object to: string enclosed by double quotes.
//
//export PLGNIDToInt
func PLGNIDToInt(jsonResponse **C.char, in *C.char,
	status **C.PLGNStatus) (ok bool) {

	_, cancel := logAPITime()
	defer cancel()

	if in == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"pointer to request is nil")
		return false
	}

	var idStr string
	err := json.Unmarshal([]byte(C.GoString(in)), &idStr)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	id, err := core.IDFromString(idStr)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	resp, err := json.Marshal(id.BigInt().Text(10))
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	*jsonResponse = C.CString(string(resp))
	return true
}

//export PLGNProofFromSmartContract
func PLGNProofFromSmartContract(jsonResponse **C.char, in *C.char,
	status **C.PLGNStatus) (ok bool) {

	_, cancel := logAPITime()
	defer cancel()

	if in == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"pointer to request is nil")
		return false
	}

	var scProof c_polygonid.SmartContractProof
	err := json.Unmarshal([]byte(C.GoString(in)), &scProof)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	proof, root, err := c_polygonid.ProofFromSmartContract(scProof)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	resp := struct {
		Root  *merkletree.Hash  `json:"root"`
		Proof *merkletree.Proof `json:"proof"`
	}{
		Root:  root,
		Proof: proof,
	}
	respB, err := json.Marshal(resp)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	*jsonResponse = C.CString(string(respB))
	return true
}

//export PLGNProfileID
func PLGNProfileID(jsonResponse **C.char, in *C.char,
	status **C.PLGNStatus) bool {

	_, cancel := logAPITime()
	defer cancel()

	if jsonResponse == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"jsonResponse pointer is nil")
		return false
	}

	var req struct {
		GenesisDID string                  `json:"genesisDID"`
		Nonce      *c_polygonid.JsonBigInt `json:"nonce"`
	}

	err := json.Unmarshal([]byte(C.GoString(in)), &req)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	did, err := w3c.ParseDID(req.GenesisDID)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	id, err := core.IDFromDID(*did)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	id, err = core.ProfileID(id, req.Nonce.BigInt())
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	profileDID, err := core.ParseDIDFromID(id)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	resp := struct {
		ProfileDID string `json:"profileDID"`
	}{ProfileDID: profileDID.String()}

	circuitInputJSON, err := json.Marshal(resp)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"response marshal error: %v", err)
		return false
	}

	*jsonResponse = C.CString(string(circuitInputJSON))
	return true
}

// PLGNAtomicQuerySigV2Inputs returns the inputs for the
// credentialAtomicQuerySigV2 with optional selective disclosure.
//
// Additional configuration may be required for Reverse Hash Service
// revocation validation. In other case cfg may be nil.
//
// The configuration example may be found in the [README.md] file.
//
// [README.md]: https://github.com/0xPolygonID/c-polygonid/blob/main/README.md#configuration
//
//export PLGNAtomicQuerySigV2Inputs
func PLGNAtomicQuerySigV2Inputs(jsonResponse **C.char, in *C.char, cfg *C.char,
	status **C.PLGNStatus) bool {

	ctx, cancel := logAPITime()
	defer cancel()

	return prepareInputs(ctx, c_polygonid.AtomicQuerySigV2InputsFromJson,
		jsonResponse, in, cfg, status)
}

// PLGNSigV2Inputs returns the inputs for the Sig circuit v2 with
// optional selective disclosure.
//
// Deprecated: Does not support Reverse Hash Service credential status
// validation! Use PLGNAtomicQuerySigV2Inputs method with configuration instead.
//
//export PLGNSigV2Inputs
func PLGNSigV2Inputs(jsonResponse **C.char, in *C.char,
	status **C.PLGNStatus) bool {

	ctx, cancel := logAPITime()
	defer cancel()

	if jsonResponse == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"jsonResponse pointer is nil")
		return false
	}

	ctx, ctxCancel := context.WithTimeout(ctx, defaultTimeout)
	defer ctxCancel()

	inData := C.GoBytes(unsafe.Pointer(in), C.int(C.strlen(in)))

	aqInpResp, err := c_polygonid.AtomicQuerySigV2InputsFromJson(ctx,
		c_polygonid.EnvConfig{}, inData)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	resp, err := marshalInputsResponse(aqInpResp)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"error marshalling atomic query inputs: %v", err)
		return false
	}

	*jsonResponse = C.CString(resp)
	return true
}

func marshalInputsResponse(
	inputsResponse c_polygonid.AtomicQueryInputsResponse) (string, error) {

	var resp struct {
		Inputs                 json.RawMessage `json:"inputs"`
		VerifiablePresentation any             `json:"verifiablePresentation,omitempty"`
	}
	if inputsResponse.VerifiablePresentation != nil {
		resp.VerifiablePresentation = inputsResponse.VerifiablePresentation
	}
	var err error
	resp.Inputs, err = inputsResponse.Inputs.InputsMarshal()
	if err != nil {
		return "", err
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		return "", err
	}

	return string(respBytes), nil

}

// PLGNAtomicQueryMtpV2Inputs returns the inputs for the
// credentialAtomicQueryMTPV2 with optional selective disclosure.
//
// Additional configuration may be required for Reverse Hash Service
// revocation validation. In other case cfg may be nil.
//
// The configuration example may be found in the [README.md] file.
//
// [README.md]: https://github.com/0xPolygonID/c-polygonid/blob/main/README.md#configuration
//
//export PLGNAtomicQueryMtpV2Inputs
func PLGNAtomicQueryMtpV2Inputs(jsonResponse **C.char, in *C.char, cfg *C.char,
	status **C.PLGNStatus) bool {

	ctx, cancel := logAPITime()
	defer cancel()

	return prepareInputs(ctx, c_polygonid.AtomicQueryMtpV2InputsFromJson,
		jsonResponse, in, cfg, status)
}

// PLGNMtpV2Inputs returns the inputs for the MTP circuit v2 with
// optional selective disclosure.
//
// Deprecated: Does not support Reverse Hash Service credential status
// validation! Use PLGNAtomicQueryMtpV2Inputs method with configuration instead.
//
//export PLGNMtpV2Inputs
func PLGNMtpV2Inputs(jsonResponse **C.char, in *C.char,
	status **C.PLGNStatus) bool {

	ctx, cancel := logAPITime()
	defer cancel()

	ctx, ctxCancel := context.WithTimeout(ctx, defaultTimeout)
	defer ctxCancel()

	if jsonResponse == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"jsonResponse pointer is nil")
		return false
	}

	inData := C.GoBytes(unsafe.Pointer(in), C.int(C.strlen(in)))

	aqInpResp, err := c_polygonid.AtomicQueryMtpV2InputsFromJson(ctx,
		c_polygonid.EnvConfig{}, inData)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	resp, err := marshalInputsResponse(aqInpResp)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"error marshalling atomic query inputs: %v", err)
		return false
	}

	*jsonResponse = C.CString(resp)
	return true
}

// PLGNAtomicQuerySigV2OnChainInputs returns the inputs for the
// credentialAtomicQuerySigV2OnChain circuit with optional selective disclosure.
//
// Additional configuration may be required for Reverse Hash Service
// revocation validation. In other case cfg may be nil.
//
// The configuration example may be found in the [README.md] file.
//
// [README.md]: https://github.com/0xPolygonID/c-polygonid/blob/main/README.md#configuration
//
//export PLGNAtomicQuerySigV2OnChainInputs
func PLGNAtomicQuerySigV2OnChainInputs(jsonResponse **C.char, in *C.char,
	cfg *C.char, status **C.PLGNStatus) bool {

	ctx, cancel := logAPITime()
	defer cancel()

	return prepareInputs(ctx, c_polygonid.AtomicQuerySigV2OnChainInputsFromJson,
		jsonResponse, in, cfg, status)
}

// PLGNAtomicQueryMtpV2OnChainInputs returns the inputs for the
// credentialAtomicQueryMTPV2OnChain circuit with optional selective disclosure.
//
// Additional configuration may be required for Reverse Hash Service
// revocation validation. In other case cfg may be nil.
//
// The configuration example may be found in the [README.md] file.
//
// [README.md]: https://github.com/0xPolygonID/c-polygonid/blob/main/README.md#configuration
//
//export PLGNAtomicQueryMtpV2OnChainInputs
func PLGNAtomicQueryMtpV2OnChainInputs(jsonResponse **C.char, in *C.char,
	cfg *C.char, status **C.PLGNStatus) bool {

	ctx, cancel := logAPITime()
	defer cancel()

	return prepareInputs(ctx, c_polygonid.AtomicQueryMtpV2OnChainInputsFromJson,
		jsonResponse, in, cfg, status)
}

// PLGNAtomicQueryV3Inputs returns the inputs for the credentialAtomicQueryV3
// circuit with optional selective disclosure.
//
//export PLGNAtomicQueryV3Inputs
func PLGNAtomicQueryV3Inputs(jsonResponse **C.char, in *C.char,
	cfg *C.char, status **C.PLGNStatus) bool {

	ctx, cancel := logAPITime()
	defer cancel()

	return prepareInputs(ctx, c_polygonid.AtomicQueryV3InputsFromJson,
		jsonResponse, in, cfg, status)
}

// PLGNAtomicQueryV3OnChainInputs returns the inputs for the
// credentialAtomicQueryV3OnChain circuit with optional selective disclosure.
//
//export PLGNAtomicQueryV3OnChainInputs
func PLGNAtomicQueryV3OnChainInputs(jsonResponse **C.char, in *C.char,
	cfg *C.char, status **C.PLGNStatus) bool {

	ctx, cancel := logAPITime()
	defer cancel()

	return prepareInputs(ctx, c_polygonid.AtomicQueryV3OnChainInputsFromJson,
		jsonResponse, in, cfg, status)
}

//export PLGNFreeStatus
func PLGNFreeStatus(status *C.PLGNStatus) {
	_, cancel := logAPITime()
	defer cancel()

	if status == nil {
		return
	}

	if status.error_msg != nil {
		C.free(unsafe.Pointer(status.error_msg))
	}

	C.free(unsafe.Pointer(status))
}

//export PLGNCleanCache
func PLGNCleanCache(status **C.PLGNStatus) bool {
	_, cancel := logAPITime()
	defer cancel()

	err := c_polygonid.CleanCache()
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	return true
}

//export PLGNCacheCredentials
func PLGNCacheCredentials(in *C.char, cfg *C.char, status **C.PLGNStatus) bool {
	ctx, cancel := logAPITime()
	defer cancel()

	ctx, ctxCancel := context.WithTimeout(ctx, defaultTimeout)
	defer ctxCancel()

	inData := C.GoBytes(unsafe.Pointer(in), C.int(C.strlen(in)))

	envCfg, err := createEnvConfig(cfg)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	err = c_polygonid.PreCacheVC(ctx, envCfg, inData)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	return true
}

// PLGNW3CCredentialFromOnchainHex returns a verifiable credential from an onchain data hex string.
//
// Sample input:
//
//	{
//	   "issuerDID": "did:polygonid:polygon:mumbai:2qCU58EJgrEMJvPfhUCnFCwuKQTkX8VmJX2sJCH6C8",
//	   "hexdata": "0x0...",
//	   "version": "0.0.1"
//	}
//
// The configuration example may be found in the [README.md] file.
//
// [README.md]: https://github.com/0xPolygonID/c-polygonid/blob/main/README.md#configuration
//
//export PLGNW3CCredentialFromOnchainHex
func PLGNW3CCredentialFromOnchainHex(jsonResponse **C.char, in *C.char,
	cfg *C.char, status **C.PLGNStatus) bool {

	if jsonResponse == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"jsonResponse pointer is nil")
		return false
	}

	if in == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"pointer to request is nil")
		return false
	}

	ctx, cancel := logAPITime()
	defer cancel()

	ctx2, cancel2 := context.WithTimeout(ctx, defaultTimeout)
	defer cancel2()

	inData := C.GoBytes(unsafe.Pointer(in), C.int(C.strlen(in)))

	envCfg, err := createEnvConfig(cfg)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	credential, err := c_polygonid.W3CCredentialFromOnchainHex(
		ctx2,
		envCfg,
		inData,
	)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	*jsonResponse = C.CString(string(credentialJSON))
	return true
}

// PLGNDescribeID parses ID and return it in different representations.
// Request example:
//
// {"id":"31Akw5AB2xBrwqmbDUA2XoSGCfTepz52q9jmFE4mXA"}
//
// {"idAsInt":"24460059377712687587111979692736628604804094576108957842967948238113620738"}
//
// There is possible to pass both id & idAsInt fields in the request. But if the
// resulted ID would not be equal, error returns.
//
// Response example:
//
//	{
//	  "did":     "did:polygonid:linea:testnet:31Akw5AB2xBrwqmbDUA2XoSGCfTepz52q9jmFE4mXA",
//	  "id":      "31Akw5AB2xBrwqmbDUA2XoSGCfTepz52q9jmFE4mXA",
//	  "idAsInt": "24460059377712687587111979692736628604804094576108957842967948238113620738",
//	}
//
//export PLGNDescribeID
func PLGNDescribeID(jsonResponse **C.char, in *C.char, cfg *C.char,
	status **C.PLGNStatus) (ok bool) {

	ctx, cancel := logAPITime()
	defer cancel()

	if in == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"pointer to request is nil")
		return false
	}

	envCfg, err := createEnvConfig(cfg)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	inBytes := C.GoString(in)
	resp, err := c_polygonid.DescribeID(ctx, envCfg, inBytes)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	respB, err := json.Marshal(resp)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	*jsonResponse = C.CString(string(respB))
	return true
}

// createEnvConfig returns empty config if input json is nil.
func createEnvConfig(cfgJson *C.char) (c_polygonid.EnvConfig, error) {
	var cfgData []byte
	if cfgJson != nil {
		cfgData = C.GoBytes(unsafe.Pointer(cfgJson), C.int(C.strlen(cfgJson)))
	}
	return c_polygonid.NewEnvConfigFromJSON(cfgData)
}

type atomicQueryInputsFn func(ctx context.Context, cfg c_polygonid.EnvConfig,
	in []byte) (c_polygonid.AtomicQueryInputsResponse, error)

func prepareInputs(ctx context.Context, fn atomicQueryInputsFn,
	jsonResponse **C.char, in *C.char, cfg *C.char,
	status **C.PLGNStatus) bool {
	if jsonResponse == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"jsonResponse pointer is nil")
		return false
	}

	var cancel func()
	ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
	defer cancel()

	inData := C.GoBytes(unsafe.Pointer(in), C.int(C.strlen(in)))

	envCfg, err := createEnvConfig(cfg)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	aqInpResp, err := fn(ctx, envCfg, inData)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	resp, err := marshalInputsResponse(aqInpResp)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR,
			"error marshalling atomic query inputs: %v", err)
		return false
	}

	*jsonResponse = C.CString(resp)
	return true
}

const debug = false
const tracing = false

func getFuncName(skip int) string {
	pc, _, _, ok := runtime.Caller(skip)
	if !ok {
		fmt.Println("Failed to get the caller information")
		return ""
	}

	funcName := runtime.FuncForPC(pc).Name()
	parts := strings.Split(funcName, ".")
	return parts[len(parts)-1]
}

func logAPITime() (context.Context, func()) {
	ctx := context.Background()

	if !debug && !tracing {
		return ctx, func() {}
	}

	var taskCanceler interface{ End() }
	funcName := getFuncName(2)

	if tracing {
		ctx, taskCanceler = trace.NewTask(ctx, funcName)
	}

	var start time.Time
	if debug {
		start = time.Now()
	}

	return ctx, func() {
		if taskCanceler != nil {
			taskCanceler.End()
		}

		if start.IsZero() {
			fmt.Printf("[%v] API call took %v\n", funcName,
				time.Since(start))
		}
	}
}

func main() {}
