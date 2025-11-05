package c_polygonid

import (
	"context"
	"encoding/json"
	"errors"

	gocircuitexternal "github.com/0xPolygonID/go-circuit-external/AnonAadhaar"
)

type anonAadhaarV1Inputs struct {
	QRData *jsonNumber `json:"qrData"`
	gocircuitexternal.AnonAadhaarV1Inputs
}

func (a *anonAadhaarV1Inputs) asAnonAadhaarV1Inputs() *gocircuitexternal.AnonAadhaarV1Inputs {
	a.AnonAadhaarV1Inputs.QRData = a.QRData.toBitInt()
	return &a.AnonAadhaarV1Inputs
}

type AnonAadhaarValidQRResponse struct {
	IsValid bool `json:"isValid"`
}

func VerifyAnonAadhaarQR(ctx context.Context, cfg EnvConfig, in []byte) (AnonAadhaarValidQRResponse, error) {
	payload := anonAadhaarV1Inputs{}
	if err := json.Unmarshal(in, &payload); err != nil {
		return AnonAadhaarValidQRResponse{}, err
	}

	if payload.QRData == nil {
		return AnonAadhaarValidQRResponse{}, errors.New("qrData is required")
	}

	a := gocircuitexternal.AnonAadhaarDataV2{}
	if err := a.UnmarshalQR(payload.QRData.toBitInt()); err != nil {
		return AnonAadhaarValidQRResponse{}, err
	}

	return AnonAadhaarValidQRResponse{IsValid: true}, nil
}
