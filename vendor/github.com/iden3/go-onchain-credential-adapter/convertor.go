package convertor

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/iden3/go-iden3-core/v2/w3c"
	adapterV0 "github.com/iden3/go-onchain-credential-adapter/adapter/v0"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

// Options contains options for the W3CCredentialFromOnchainHex convertor.
type Options struct {
	MerklizeOptions merklize.Options
}

// Option is a functional option for the W3CCredentialFromOnchainHex convertor.
type Option func(*Options)

// WithMerklizeOptions sets the merklize options for the convertor.
func WithMerklizeOptions(options merklize.Options) Option {
	return func(o *Options) {
		o.MerklizeOptions = options
	}
}

// W3CCredentialFromOnchainHex converts an onchain hex data to a W3C credential.
func W3CCredentialFromOnchainHex(
	ctx context.Context,
	ethcli *ethclient.Client,
	issuerDID *w3c.DID,
	hexdata string,
	version string,
	options ...Option,
) (*verifiable.W3CCredential, error) {
	opts := &Options{}
	for _, o := range options {
		o(opts)
	}

	majorVersion, err := getMajorVersion(version)
	if err != nil {
		return nil, fmt.Errorf("failed to get major version: %w", err)
	}

	// nolint: gocritic // the switch for changes in the future
	switch majorVersion {
	case 0:
		aV0, err := adapterV0.New(
			ctx,
			ethcli,
			issuerDID,
			opts.MerklizeOptions,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create adapter: %w", err)
		}
		return aV0.HexToW3CCredential(ctx, hexdata)
	}

	return nil, fmt.Errorf("unsupported major version '%d'", majorVersion)
}

func getMajorVersion(version string) (int, error) {
	versionParts := strings.Split(version, ".")
	if len(versionParts) != 3 {
		return 0, fmt.Errorf("invalid version format '%s'", version)
	}

	major, err := strconv.Atoi(versionParts[0])
	if err != nil {
		return 0, fmt.Errorf("failed to parse major version '%s': %w", version, err)
	}

	return major, nil
}
