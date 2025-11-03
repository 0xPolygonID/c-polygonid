package c_polygonid

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/iden3/go-iden3-core/v2/w3c"
)

type CredentialStatusCheckResponse struct {
	Valid bool `json:"valid"`
}

func CredentialStatusCheck(ctx context.Context, cfg EnvConfig,
	jsonReq []byte) (CredentialStatusCheckResponse, error) {

	var req struct {
		IssuerDID        *w3c.DID `json:"issuer"`
		UserDID          *w3c.DID `json:"user"`
		CredentialStatus jsonObj  `json:"credentialStatus"`
	}

	err := json.Unmarshal(jsonReq, &req)
	if err != nil {
		return CredentialStatusCheckResponse{}, err
	}

	_, err = buildAndValidateCredentialStatus(ctx, cfg, req.CredentialStatus,
		req.IssuerDID, req.UserDID, false)
	if errors.Is(err, errCredentialsRevoked) {
		return CredentialStatusCheckResponse{}, nil
	} else if err != nil {
		return CredentialStatusCheckResponse{}, err
	}
	return CredentialStatusCheckResponse{Valid: true}, nil
}
