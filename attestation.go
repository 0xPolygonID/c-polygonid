package c_polygonid

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/go-cose"
)

var msnRootCertFingerprint = [32]byte{
	0x64, 0x1A, 0x03, 0x21, 0xA3, 0xE2, 0x44, 0xEF,
	0xE4, 0x56, 0x46, 0x31, 0x95, 0xD6, 0x06, 0x31,
	0x7E, 0xD7, 0xCD, 0xCC, 0x3C, 0x17, 0x56, 0xE0,
	0x98, 0x93, 0xF3, 0xC6, 0x8F, 0x79, 0xBB, 0x5B}

type ValidateAttestationDocumentResponse struct {
	PublicKey  string `json:"public_key"`
	PublicKeyX string `json:"public_key_x_int,omitempty"`
	PublicKeyY string `json:"public_key_y_int,omitempty"`
}

type ValidateAttestationDocumentRequest struct {
	Doc base64Data `json:"attestation_document"`
}

type base64Data []byte

func (v *base64Data) UnmarshalJSON(bytes []byte) error {
	var s string
	if err := json.Unmarshal(bytes, &s); err != nil {
		return err
	}
	var err error
	*v, err = base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("error decoding base64: %w", err)
	}
	return nil
}

func ValidateAttestationDocument(_ context.Context, _ EnvConfig,
	in []byte) (ValidateAttestationDocumentResponse, error) {

	var req ValidateAttestationDocumentRequest
	err := json.Unmarshal(in, &req)
	if err != nil {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"unable to parse json request: %w", err)
	}
	var msg cose.UntaggedSign1Message
	err = msg.UnmarshalCBOR(req.Doc)
	if err != nil {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"unable to parse attestation document: %w", err)
	}

	algorithm, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"unable to get algorithm from attestation document: %w", err)
	}

	var docContents struct {
		Cert     []byte   `cbor:"certificate"`
		CaBundle [][]byte `cbor:"cabundle"`
	}
	err = cbor.Unmarshal(msg.Payload, &docContents)
	if err != nil {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"unable to parse attestation document payload: %w", err)
	}

	if len(docContents.CaBundle) == 0 {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"no CA bundle found in attestation document")
	}

	if len(docContents.Cert) == 0 {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"no certificate found in attestation document")
	}

	leafCert, err := x509.ParseCertificate(docContents.Cert)
	if err != nil {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"unable to parse attestation certificate: %w", err)
	}

	rootPool := x509.NewCertPool()
	intermediatePool := x509.NewCertPool()
	rootCertFound := false

	for _, caCert := range docContents.CaBundle {
		caCertParsed, err := x509.ParseCertificate(caCert)
		if err != nil {
			return ValidateAttestationDocumentResponse{}, fmt.Errorf(
				"unable to parse CA bundle certificate: %w", err)
		}
		certChkSum := sha256.Sum256(caCertParsed.Raw)
		if certChkSum == msnRootCertFingerprint {
			rootPool.AddCert(caCertParsed)
			rootCertFound = true
		} else {
			intermediatePool.AddCert(caCertParsed)
		}
	}

	if !rootCertFound {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"NSM root certificate not found in CA bundle")
	}

	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots:         rootPool,
		Intermediates: intermediatePool,
	})
	if err != nil {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"failed to verify attestation certificate chain: %w", err)
	}

	verifier, err := cose.NewVerifier(algorithm, leafCert.PublicKey)
	if err != nil {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"failed to create verifier: %w", err)
	}
	err = msg.Verify(nil, verifier)
	if err != nil {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"failed to verify attestation document: %w", err)
	}

	var resp ValidateAttestationDocumentResponse

	pubKey, err := x509.MarshalPKIXPublicKey(leafCert.PublicKey)
	if err != nil {
		return ValidateAttestationDocumentResponse{}, fmt.Errorf(
			"failed to marshal public key: %w", err)
	}

	resp.PublicKey = base64.StdEncoding.EncodeToString(pubKey)

	switch pk := leafCert.PublicKey.(type) {
	case *ecdsa.PublicKey:
		resp.PublicKeyX = pk.X.String()
		resp.PublicKeyY = pk.Y.String()
	}

	return resp, nil
}
