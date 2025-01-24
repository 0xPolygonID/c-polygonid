package resolvers

import (
	"bytes"
	"context"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	mp "github.com/iden3/merkletree-proof/http"
	"github.com/pkg/errors"
)

// RHSResolver is a struct that allows to interact with the RHS service to get revocation status.
type RHSResolver struct {
	ethClients             map[core.ChainID]*ethclient.Client
	stateContractAddresses map[core.ChainID]common.Address
}

// NewRHSResolver returns new RHS resolver
func NewRHSResolver(ethClients map[core.ChainID]*ethclient.Client, stateContractAddresses map[core.ChainID]common.Address) *RHSResolver {
	return &RHSResolver{
		ethClients:             ethClients,
		stateContractAddresses: stateContractAddresses,
	}
}

// Resolve is a method to resolve a credential status from the RHS.
func (r RHSResolver) Resolve(ctx context.Context,
	status verifiable.CredentialStatus) (out verifiable.RevocationStatus, err error) {

	if status.Type != verifiable.Iden3ReverseSparseMerkleTreeProof {
		return out, errors.New("invalid status type")
	}

	issuerDID := verifiable.GetIssuerDID(ctx)
	if issuerDID == nil {
		return out, errors.New("issuer DID is not set in context")
	}

	issuerID, err := core.IDFromDID(*issuerDID)
	if err != nil {
		return out, err
	}

	revNonce := new(big.Int).SetUint64(status.RevocationNonce)

	baseRHSURL, genesisState, err := rhsBaseURL(status.ID)
	if err != nil {
		return out, err
	}

	ethClient, err := getEthClientForDID(issuerDID, r.ethClients)
	if err != nil {
		return out, err
	}

	stateAddr, err := getStateContractForDID(issuerDID, r.stateContractAddresses)
	if err != nil {
		return out, err
	}
	state, err := identityStateForRHS(ctx, stateAddr, ethClient, &issuerID, genesisState)
	if err != nil {
		return out, err
	}

	rhsCli, err := newRhsCli(baseRHSURL)
	if err != nil {
		return out, err
	}

	out.Issuer, err = issuerFromRHS(ctx, *rhsCli, state)
	if errors.Is(err, mp.ErrNodeNotFound) {
		if genesisState != nil && state.Equals(genesisState) {
			return out, errors.New("genesis state is not found in RHS")
		} else {
			return out, errors.New("current state is not found in RHS")
		}
	} else if err != nil {
		return out, err
	}

	revNonceHash, err := merkletree.NewHashFromBigInt(revNonce)
	if err != nil {
		return out, err
	}

	revTreeRootHash, err := merkletree.NewHashFromHex(*out.Issuer.RevocationTreeRoot)
	if err != nil {
		return out, err
	}
	proof, err := rhsCli.GenerateProof(ctx, revTreeRootHash,
		revNonceHash)
	if err != nil {
		return out, err
	}

	out.MTP = *proof

	return out, nil
}

func identityStateForRHS(ctx context.Context, stateAddr common.Address, ethClient *ethclient.Client, issuerID *core.ID,
	genesisState *merkletree.Hash) (*merkletree.Hash, error) {

	state, err := lastStateFromContract(ctx, stateAddr, ethClient, issuerID)
	if !errors.Is(err, errIdentityDoesNotExist) {
		return state, err
	}

	if genesisState == nil {
		return nil, errors.New("current state is not found for the identity")
	}

	stateIsGenesis, err := genesisStateMatch(genesisState, *issuerID)
	if err != nil {
		return nil, err
	}

	if !stateIsGenesis {
		return nil, errors.New("state is not genesis for the identity")
	}

	return genesisState, nil
}

// check if genesis state matches the state from the ID
func genesisStateMatch(state *merkletree.Hash, id core.ID) (bool, error) {
	var tp [2]byte
	copy(tp[:], id[:2])
	otherID, err := core.NewIDFromIdenState(tp, state.BigInt())
	if err != nil {
		return false, err
	}
	return bytes.Equal(otherID[:], id[:]), nil
}

func issuerFromRHS(ctx context.Context, rhsCli mp.ReverseHashCli,
	state *merkletree.Hash) (verifiable.TreeState, error) {

	var issuer verifiable.TreeState

	stateNode, err := rhsCli.GetNode(ctx, state)
	if err != nil {
		return issuer, err
	}

	if len(stateNode.Children) != 3 {
		return issuer, errors.New(
			"invalid state node, should have 3 children")
	}

	stateHex := state.Hex()
	issuer.State = &stateHex
	claimsTreeRootHex := stateNode.Children[0].Hex()
	issuer.ClaimsTreeRoot = &claimsTreeRootHex
	revocationTreeRootHex := stateNode.Children[1].Hex()
	issuer.RevocationTreeRoot = &revocationTreeRootHex
	rootOfRootsHex := stateNode.Children[2].Hex()
	issuer.RootOfRoots = &rootOfRootsHex

	return issuer, err
}

func newRhsCli(rhsURL string) (*mp.ReverseHashCli, error) {
	if rhsURL == "" {
		return nil, errors.New("reverse hash service url is empty")
	}

	return &mp.ReverseHashCli{
		URL:         rhsURL,
		HTTPTimeout: 10 * time.Second,
	}, nil
}

func rhsBaseURL(rhsURL string) (string, *merkletree.Hash, error) {
	u, err := url.Parse(rhsURL)
	if err != nil {
		return "", nil, err
	}
	var state *merkletree.Hash
	stateStr := u.Query().Get("state")
	if stateStr != "" {
		state, err = merkletree.NewHashFromHex(stateStr)
		if err != nil {
			return "", nil, err
		}
	}

	if strings.HasSuffix(u.Path, "/node") {
		u.Path = strings.TrimSuffix(u.Path, "node")
	}
	if strings.HasSuffix(u.Path, "/node/") {
		u.Path = strings.TrimSuffix(u.Path, "node/")
	}

	u.RawQuery = ""
	return u.String(), state, nil
}
