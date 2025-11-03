package c_polygonid

import (
	"context"
	"encoding/json"
	"fmt"

	auth "github.com/iden3/go-iden3-auth/v2"
	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/iden3comm/v2/protocol"
)

type proofVerification struct {
	AuthRequest  protocol.AuthorizationRequestMessage `json:"auth_request"`
	AuthResponse string                               `json:"auth_response"`
}

// VerifyAuthResponse verifies an authorization response using the provided environment configuration.
func VerifyAuthResponse(ctx context.Context, cfg EnvConfig, in []byte) (protocol.AuthorizationResponseMessage, error) {
	var p proofVerification
	err := json.Unmarshal(in, &p)
	if err != nil {
		return protocol.AuthorizationResponseMessage{},
			fmt.Errorf("failed to unmarshal proof verification: %w", err)
	}

	resolvers := make(map[string]pubsignals.StateResolver, len(cfg.ChainConfigs))
	for chainID, chainCfg := range cfg.ChainConfigs {
		resolver, err := state.NewETHResolverWithOpts(
			chainCfg.RPCUrl,
			chainCfg.StateContractAddr.Hex(),
		)
		if err != nil {
			return protocol.AuthorizationResponseMessage{},
				fmt.Errorf("failed to create ETH state resolver for chainID %v: %w", chainID, err)
		}
		c, n, err := core.NetworkByChainID(chainID)
		if err != nil {
			return protocol.AuthorizationResponseMessage{},
				fmt.Errorf("failed to get network for chainID %v: %w", chainID, err)
		}
		resolvers[fmt.Sprintf("%s:%s", c, n)] = resolver
	}

	keyloader := loaders.NewEmbeddedKeyLoader()
	opts := []auth.VerifierOption{
		auth.WithDocumentLoader(cfg.documentLoader()),
	}

	verifier, err := auth.NewVerifier(keyloader, resolvers, opts...)
	if err != nil {
		return protocol.AuthorizationResponseMessage{},
			fmt.Errorf("failed to create auth verifier: %w", err)
	}

	authResponseMessage, err := verifier.FullVerify(ctx, p.AuthResponse, p.AuthRequest)
	if err != nil {
		return protocol.AuthorizationResponseMessage{},
			fmt.Errorf("failed to verify auth response: %w", err)
	}

	return *authResponseMessage, nil
}
