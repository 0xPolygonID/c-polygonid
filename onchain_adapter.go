package c_polygonid

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/ethereum/go-ethereum/ethclient"
	core "github.com/iden3/go-iden3-core/v2"
	convertor "github.com/iden3/go-onchain-credential-adapter"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

type w3CCredentialFromOnchainHexRequest struct {
	ContractAddress string `json:"contractAddress"`
	ChainID         int32  `json:"chainID"`
	Hexdata         string `json:"hexdata"`
	Version         string `json:"version"`
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

	chainConfig, ok := envCfg.ChainConfigs[core.ChainID(inParams.ChainID)]
	if !ok {
		return nil, fmt.Errorf("chain id '%d' not found in config", inParams.ChainID)
	}

	ethcli, err := ethclient.DialContext(ctx, chainConfig.RPCUrl)
	if err != nil {
		return nil,
			fmt.Errorf("failed to connect to ethereum: %w", err)
	}
	defer ethcli.Close()

	credential, err := convertor.W3CCredentialFromOnchainHex(
		ctx,
		ethcli,
		inParams.ContractAddress,
		inParams.ChainID,
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
