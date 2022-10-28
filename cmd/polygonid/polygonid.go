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
	"unsafe"

	"github.com/iden3/go-circuits"
)

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
