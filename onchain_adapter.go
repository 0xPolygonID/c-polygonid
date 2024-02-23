package c_polygonid

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	convertor "github.com/iden3/go-onchain-credential-adapter"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

type w3CCredentialFromOnchainHexRequest struct {
	IssuerDID coreDID `json:"issuerDID"`
	Hexdata   string  `json:"hexdata"`
	Version   string  `json:"version"`
}

func W3CCredentialFromOnchainHex(
	ctx context.Context,
	envCfg EnvConfig,
	in []byte,
) (*verifiable.W3CCredential, error) {
	var inParams w3CCredentialFromOnchainHexRequest
	if err := json.Unmarshal(in, &inParams); err != nil {
		return nil, fmt.Errorf("failed to unmarshal input params: %w", err)
	}

	issuerDID := w3c.DID(inParams.IssuerDID)

	chainID, err := core.ChainIDfromDID(issuerDID)
	if err != nil {
		return nil, fmt.Errorf("failed to get chain id from issuer: %w", err)
	}
	chainConfig, ok := envCfg.ChainConfigs[chainID]
	if !ok {
		return nil, fmt.Errorf("chain id '%d' not found in config", chainID)
	}

	ethcli, err := ethclient.DialContext(ctx, chainConfig.RPCUrl)
	if err != nil {
		return nil,
			fmt.Errorf("failed to connect to ethereum: %w", err)
	}

	credential, err := convertor.W3CCredentialFromOnchainHex(
		ctx,
		ethcli,
		&issuerDID,
		inParams.Hexdata,
		inParams.Version,
		convertor.WithMerklizeOptions(
			merklize.Options{
				DocumentLoader: envCfg.documentLoader(),
			},
		),
	)
	if err != nil {
		return nil,
			fmt.Errorf("failed to convert onchain hex to W3C credential: %w", err)
	}
	return credential, nil
}
