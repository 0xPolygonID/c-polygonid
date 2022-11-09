package main

/*
#include <stdlib.h>

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
	"encoding/json"
	"fmt"
	"math/big"
	"unsafe"

	"github.com/iden3/go-circuits"
	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-merkletree-sql/v2"
)

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

	if jsonResponse == nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_NIL_POINTER,
			"jsonResponse pointer is nil")
		return false
	}

	in2 := C.GoString(in)
	var inputs circuits.AuthV2Inputs
	err := json.Unmarshal([]byte(in2), &inputs)
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

//export PLGNCalculateGenesisID
func PLGNCalculateGenesisID(jsonResponse **C.char, in *C.char,
	status **C.PLGNStatus) bool {

	var req struct {
		ClaimsTreeRoot *jsonIntStr     `json:"claimsTreeRoot"`
		Blockchain     core.Blockchain `json:"blockchain"`
		Network        core.NetworkID  `json:"network"`
	}

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

	state, err := merkletree.HashElems(req.ClaimsTreeRoot.Int(),
		merkletree.HashZero.BigInt(), merkletree.HashZero.BigInt())
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	typ, err := core.BuildDIDType(core.DIDMethodIden3, req.Blockchain,
		req.Network)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	coreID, err := core.IdGenesisFromIdenState(typ, state.BigInt())
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	did := core.DID{
		ID:         *coreID,
		Method:     core.DIDMethodIden3,
		Blockchain: req.Blockchain,
		NetworkID:  req.Network,
	}

	resp := struct {
		DID string `json:"did"`
		ID  string `json:"id"`
	}{
		DID: did.String(),
		ID:  coreID.String(),
	}
	respB, err := json.Marshal(resp)
	if err != nil {
		maybeCreateStatus(status, C.PLGNSTATUSCODE_ERROR, err.Error())
		return false
	}

	*jsonResponse = C.CString(string(respB))
	return true
}

//export PLGNFreeStatus
func PLGNFreeStatus(status *C.PLGNStatus) {
	if status == nil {
		return
	}

	if status.error_msg != nil {
		C.free(unsafe.Pointer(status.error_msg))
	}

	C.free(unsafe.Pointer(status))
}

func main() {}
