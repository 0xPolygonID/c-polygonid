package c_polygonid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	auth "github.com/iden3/go-iden3-auth/v2"
	"github.com/iden3/go-iden3-auth/v2/loaders"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	"github.com/iden3/go-iden3-auth/v2/state"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/lestrrat-go/jwx/v3/jwk"
)

type proofVerificationOptions struct {
	AcceptedStateTransitionDelay string `json:"acceptedStateTransitionDelay"`
	AcceptedProofGenerationDelay string `json:"acceptedProofGenerationDelay"`
}
type proofVerification struct {
	AuthRequest  protocol.AuthorizationRequestMessage `json:"authRequest"`
	AuthResponse json.RawMessage                      `json:"authResponse"`
	KeySet       json.RawMessage                      `json:"keySet"`
	Options      proofVerificationOptions             `json:"options"`
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

	verificationOptions := []pubsignals.VerifyOpt{}
	if p.Options.AcceptedStateTransitionDelay != "" {
		d, err := time.ParseDuration(p.Options.AcceptedStateTransitionDelay)
		if err != nil {
			return protocol.AuthorizationResponseMessage{},
				fmt.Errorf("failed to parse accepted state transition delay: %w", err)
		}
		o := pubsignals.WithAcceptedStateTransitionDelay(d)
		verificationOptions = append(verificationOptions, o)
	}
	if p.Options.AcceptedProofGenerationDelay != "" {
		d, err := time.ParseDuration(p.Options.AcceptedProofGenerationDelay)
		if err != nil {
			return protocol.AuthorizationResponseMessage{},
				fmt.Errorf("failed to parse accepted proof generation delay: %w", err)
		}
		o := pubsignals.WithAcceptedProofGenerationDelay(d)
		verificationOptions = append(verificationOptions, o)
	}

	keyloader := loaders.NewEmbeddedKeyLoader()
	opts := []auth.VerifierOption{
		auth.WithDocumentLoader(cfg.documentLoader()),
		auth.WithStateVerificationOpts(verificationOptions...),
	}

	verifier, err := auth.NewVerifier(keyloader, resolvers, opts...)
	if err != nil {
		return protocol.AuthorizationResponseMessage{},
			fmt.Errorf("failed to create auth verifier: %w", err)
	}

	verifier.SetPacker(&packers.PlainMessagePacker{})
	if len(p.KeySet) > 0 {
		keySet, err := jwk.Parse(p.KeySet)
		if err != nil {
			return protocol.AuthorizationResponseMessage{},
				fmt.Errorf("failed to parse key set: %w", err)
		}
		resolveKeyFn := func(_ string) (interface{}, error) {
			if keySet.Len() != 1 {
				return nil, errors.New("key set must contain exactly one key")
			}
			key, ok := keySet.Key(0)
			if !ok || key == nil {
				return nil, errors.New("key idx: 0 not found in key set")
			}
			return key, nil
		}

		if err = verifier.SetPacker(packers.NewAnoncryptPacker(resolveKeyFn, nil)); err != nil {
			return protocol.AuthorizationResponseMessage{},
				fmt.Errorf("failed to set anoncrypt packer: %w", err)
		}
	}

	authResponseMessage, err := verifier.FullVerify(
		ctx, string(p.AuthResponse), p.AuthRequest, verificationOptions...)
	if err != nil {
		return protocol.AuthorizationResponseMessage{},
			fmt.Errorf("failed to verify auth response: %w", err)
	}

	return *authResponseMessage, nil
}
