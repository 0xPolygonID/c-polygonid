package c_polygonid

import (
	gocircuitexternal "github.com/0xPolygonID/go-circuit-external"
)

type anonAadhaarV1Inputs struct {
	QRData *jsonNumber `json:"qrData"`
	gocircuitexternal.AnonAadhaarV1Inputs
}

func (a *anonAadhaarV1Inputs) asAnonAadhaarV1Inputs() *gocircuitexternal.AnonAadhaarV1Inputs {
	a.AnonAadhaarV1Inputs.QRData = a.QRData.toBitInt()
	return &a.AnonAadhaarV1Inputs
}
