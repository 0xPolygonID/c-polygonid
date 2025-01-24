package verifiable

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/pkg/errors"
)

var ErrCredentialIsRevoked = errors.New("credential is revoked")

type credentialStatusValidationOpts struct {
	statusResolverRegistry *CredentialStatusResolverRegistry
}

type CredentialStatusValidationOption func(*credentialStatusValidationOpts) error

func WithValidationStatusResolverRegistry(
	registry *CredentialStatusResolverRegistry) CredentialStatusValidationOption {
	return func(opts *credentialStatusValidationOpts) error {
		opts.statusResolverRegistry = registry
		return nil
	}
}

// ValidateCredentialStatus resolves the credential status (possibly download
// proofs from outer world) and validates the proof. May return
// ErrCredentialIsRevoked if the credential was revoked.
func ValidateCredentialStatus(ctx context.Context, credStatus CredentialStatus,
	opts ...CredentialStatusValidationOption) (RevocationStatus, error) {

	o := &credentialStatusValidationOpts{
		statusResolverRegistry: DefaultCredentialStatusResolverRegistry,
	}
	for _, opt := range opts {
		err := opt(o)
		if err != nil {
			return RevocationStatus{}, err
		}
	}

	revocationStatus, err := resolveRevStatus(ctx, credStatus,
		o.statusResolverRegistry)
	if err != nil {
		return revocationStatus, err
	}

	treeStateOk, err := validateTreeState(revocationStatus.Issuer)
	if err != nil {
		return revocationStatus, err
	}
	if !treeStateOk {
		return revocationStatus, errors.New("signature proof: invalid tree state of the issuer while checking credential status of singing key")
	}

	revocationRootHash := &merkletree.HashZero
	if revocationStatus.Issuer.RevocationTreeRoot != nil {
		revocationRootHash, err = merkletree.NewHashFromHex(*revocationStatus.Issuer.RevocationTreeRoot)
		if err != nil {
			return revocationStatus, err
		}
	}

	revNonce := new(big.Int).SetUint64(credStatus.RevocationNonce)
	proofValid := merkletree.VerifyProof(revocationRootHash,
		&revocationStatus.MTP, revNonce, big.NewInt(0))
	if !proofValid {
		return revocationStatus, fmt.Errorf("proof validation failed. revNonce=%d", revNonce)
	}

	if revocationStatus.MTP.Existence {
		return revocationStatus, ErrCredentialIsRevoked
	}

	return revocationStatus, nil
}

func coerceCredentialStatus(credStatus any) (*CredentialStatus, error) {
	switch credStatusT := credStatus.(type) {
	case *CredentialStatus:
		return credStatusT, nil
	case CredentialStatus:
		return &credStatusT, nil
	case jsonObj:
		var credStatusTyped CredentialStatus
		err := remarshalObj(&credStatusTyped, credStatusT)
		if err != nil {
			return nil, err
		}
		if credStatusTyped.Type == "" {
			return nil, errors.New("credential status doesn't contain type")
		}
		return &credStatusTyped, nil
	default:
		return nil, errors.New("unknown credential status format")
	}
}

func resolveRevStatus(ctx context.Context, credStatus CredentialStatus,
	credStatusResolverRegistry *CredentialStatusResolverRegistry) (out RevocationStatus, err error) {

	resolver, err := credStatusResolverRegistry.Get(credStatus.Type)
	if err != nil {
		return out, err
	}

	return resolver.Resolve(ctx, credStatus)
}

// marshal/unmarshal object from one type to other
func remarshalObj(dst, src any) error {
	objBytes, err := json.Marshal(src)
	if err != nil {
		return err
	}
	return json.Unmarshal(objBytes, dst)
}

// check Issuer TreeState consistency
func validateTreeState(i TreeState) (bool, error) {
	if i.State == nil {
		return false, errors.New("state is nil")
	}

	var err error
	ctrHash := &merkletree.HashZero
	if i.ClaimsTreeRoot != nil {
		ctrHash, err = merkletree.NewHashFromHex(*i.ClaimsTreeRoot)
		if err != nil {
			return false, err
		}
	}
	rtrHash := &merkletree.HashZero
	if i.RevocationTreeRoot != nil {
		rtrHash, err = merkletree.NewHashFromHex(*i.RevocationTreeRoot)
		if err != nil {
			return false, err
		}
	}
	rorHash := &merkletree.HashZero
	if i.RootOfRoots != nil {
		rorHash, err = merkletree.NewHashFromHex(*i.RootOfRoots)
		if err != nil {
			return false, err
		}
	}

	wantState, err := poseidon.Hash([]*big.Int{ctrHash.BigInt(),
		rtrHash.BigInt(), rorHash.BigInt()})
	if err != nil {
		return false, err
	}

	stateHash, err := merkletree.NewHashFromHex(*i.State)
	if err != nil {
		return false, err
	}
	return wantState.Cmp(stateHash.BigInt()) == 0, nil
}
