package c_polygonid

import (
	"context"
	"encoding/json"
	"errors"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
)

func CredentialStatusCheck(ctx context.Context, cfg EnvConfig,
	jsonReq []byte) (bool, error) {

	var req struct {
		IssuerDID        w3c.DID `json:"issuer"`
		CredentialStatus jsonObj `json:"credentialStatus"`
	}

	err := json.Unmarshal(jsonReq, &req)
	if err != nil {
		return false, err
	}

	issuerID, err := core.IDFromDID(req.IssuerDID)
	if err != nil {
		return false, err
	}

	_, err = buildAndValidateCredentialStatus(ctx, cfg, req.CredentialStatus,
		&issuerID, false)
	if errors.Is(err, errCredentialsRevoked) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return true, nil
}
