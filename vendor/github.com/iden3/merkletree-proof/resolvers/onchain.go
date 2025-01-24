package resolvers

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	onchainABI "github.com/iden3/contracts-abi/onchain-credential-status-resolver/go/abi"
	"github.com/iden3/contracts-abi/state/go/abi"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/utils"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/pkg/errors"
)

// OnChainResolver is a struct that allows to interact with the onchain contract and build the revocation status.
type OnChainResolver struct {
	ethClients             map[core.ChainID]*ethclient.Client
	stateContractAddresses map[core.ChainID]common.Address
}

// NewOnChainResolver returns new onChain resolver
func NewOnChainResolver(ethClients map[core.ChainID]*ethclient.Client, stateContractAddresses map[core.ChainID]common.Address) *OnChainResolver {
	return &OnChainResolver{
		ethClients:             ethClients,
		stateContractAddresses: stateContractAddresses,
	}
}

// Resolve is a method to resolve a credential status from the blockchain.
func (r OnChainResolver) Resolve(ctx context.Context,
	status verifiable.CredentialStatus) (out verifiable.RevocationStatus, err error) {

	if status.Type != verifiable.Iden3OnchainSparseMerkleTreeProof2023 {
		return out, errors.New("invalid status type")
	}

	issuerDID := verifiable.GetIssuerDID(ctx)
	if issuerDID == nil {
		return out, errors.New("issuer DID is not set in context")
	}

	issuerID, err := core.IDFromDID(*issuerDID)
	if err != nil {
		return out, errors.WithMessage((err), "can't parse issuer DID")
	}

	ethClient, err := getEthClientForDID(issuerDID, r.ethClients)
	if err != nil {
		return out, err
	}

	stateAddr, err := getStateContractForDID(issuerDID, r.stateContractAddresses)
	if err != nil {
		return out, err
	}

	onchainRevStatus, err := newOnchainRevStatusFromURI(status.ID, status.RevocationNonce)
	if err != nil {
		return out, err
	}

	contractCaller, err := onchainABI.NewOnchainCredentialStatusResolverCaller(onchainRevStatus.contractAddress, ethClient)
	if err != nil {
		return out, err
	}

	if onchainRevStatus.revNonce != status.RevocationNonce {
		return out, fmt.Errorf(
			"revocationNonce is not equal to the one "+
				"in OnChainCredentialStatus ID {%d} {%d}",
			onchainRevStatus.revNonce, status.RevocationNonce)
	}

	isStateContractHasID, err := stateContractHasID(ctx, stateAddr, ethClient, &issuerID)
	if err != nil {
		return out, err
	}

	contractOpts := &bind.CallOpts{Context: ctx}

	var resp onchainABI.IOnchainCredentialStatusResolverCredentialStatus
	if isStateContractHasID {
		resp, err = contractCaller.GetRevocationStatus(contractOpts, issuerID.BigInt(),
			onchainRevStatus.revNonce)
		if err != nil {
			msg := err.Error()
			if isErrInvalidRootsLength(err) {
				msg = "roots were not saved to identity tree store"
			}
			return out, fmt.Errorf(
				"GetRevocationProof smart contract call [GetRevocationStatus]: %s",
				msg)
		}
	} else {
		if onchainRevStatus.genesisState == nil {
			return out, errors.New(
				"genesis state is not specified in OnChainCredentialStatus ID")
		}
		resp, err = contractCaller.GetRevocationStatusByIdAndState(
			contractOpts,
			issuerID.BigInt(), onchainRevStatus.genesisState,
			onchainRevStatus.revNonce)
		if err != nil {
			return out, fmt.Errorf(
				"GetRevocationProof smart contract call [GetRevocationStatusByIdAndState]: %s",
				err.Error())
		}
	}

	return toRevocationStatus(resp)
}

func newOnchainRevStatusFromURI(statusID string, statusRevNonce uint64) (onChainRevStatus, error) {
	var s onChainRevStatus

	uri, err := url.Parse(statusID)
	if err != nil {
		return s, errors.Wrapf(err, "OnChainCredentialStatus ID is not a valid URI")
	}

	contract := uri.Query().Get("contractAddress")
	if contract == "" {
		return s, errors.New("OnChainCredentialStatus contract address is empty")
	}

	contractParts := strings.Split(contract, ":")
	if len(contractParts) != 2 {
		return s, errors.Errorf(
			"OnChainCredentialStatus contract address '%s' is not valid", contract)
	}

	s.chainID, err = newChainIDFromString(contractParts[0])
	if err != nil {
		return s, err
	}
	s.contractAddress = common.HexToAddress(contractParts[1])

	queryRevNonceString := uri.Query().Get("revocationNonce")
	if queryRevNonceString != "" {
		queryRevNonce, err := strconv.ParseUint(queryRevNonceString, 10, 64)
		if err != nil {
			return s, errors.New("query revocationNonce is not a number in OnChainCredentialStatus ID")
		}
		if queryRevNonce != statusRevNonce {
			return s, errors.New("query revocation nonce doesn't match with credential status nonce")
		}

	}

	s.revNonce = statusRevNonce

	// state may be nil if params is absent in query
	s.genesisState, err = newIntFromHexQueryParam(uri, "state")
	if err != nil {
		return s, err
	}

	return s, nil
}

func newChainIDFromString(in string) (core.ChainID, error) {
	radix := 10
	if strings.HasPrefix(in, "0x") || strings.HasPrefix(in, "0X") {
		radix = 16
		in = in[2:]
	}

	var chainID core.ChainID
	assertUnderlineTypeInt32(chainID)
	i, err := strconv.ParseInt(in, radix, 32)
	if err != nil {
		return 0, fmt.Errorf("can't parse ChainID type: %w", err)
	}
	return core.ChainID(i), nil
}

// newIntFromHexQueryParam search for query param `paramName`, parse it
// as hex string of LE bytes of *big.Int. Return nil if param is not found.
func newIntFromHexQueryParam(uri *url.URL, paramName string) (*big.Int, error) {
	stateParam := uri.Query().Get(paramName)
	if stateParam == "" {
		return nil, nil
	}

	stateParam = strings.TrimPrefix(stateParam, "0x")
	stateBytes, err := hex.DecodeString(stateParam)
	if err != nil {
		return nil, err
	}

	return newIntFromBytesLE(stateBytes), nil
}

func newIntFromBytesLE(bs []byte) *big.Int {
	return new(big.Int).SetBytes(utils.SwapEndianness(bs))
}

func stateContractHasID(ctx context.Context, stateAddr common.Address, ethClient *ethclient.Client, id *core.ID) (bool, error) {

	if idsInStateContract.has(*id) {
		return true, nil
	}

	_, err := lastStateFromContract(ctx, stateAddr, ethClient, id)
	if errors.Is(err, errIdentityDoesNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}

	idsInStateContract.add(*id)
	return true, err
}

type onChainRevStatus struct {
	chainID         core.ChainID
	contractAddress common.Address
	revNonce        uint64
	genesisState    *big.Int
}

func isErrInvalidRootsLength(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "execution reverted: Invalid roots length"
}

var errIdentityDoesNotExist = errors.New("identity does not exist")

func isErrIdentityDoesNotExist(err error) bool {
	if err == nil {
		return false
	}
	return err.Error() == "execution reverted: Identity does not exist"
}

type syncedIDsSet struct {
	sync.RWMutex
	m map[core.ID]bool
}

func (is *syncedIDsSet) has(id core.ID) bool {
	is.RLock()
	defer is.RUnlock()
	return is.m[id]
}

func (is *syncedIDsSet) add(id core.ID) {
	is.Lock()
	defer is.Unlock()
	if is.m == nil {
		is.m = make(map[core.ID]bool)
	}
	is.m[id] = true
}

var idsInStateContract syncedIDsSet

func lastStateFromContract(ctx context.Context, stateAddr common.Address, ethClient *ethclient.Client,
	id *core.ID) (*merkletree.Hash, error) {
	var zeroID core.ID
	if id == nil || *id == zeroID {
		return nil, errors.New("ID is empty")
	}

	contractCaller, err := abi.NewStateCaller(stateAddr, ethClient)
	if err != nil {
		return nil, err
	}

	opts := &bind.CallOpts{Context: ctx}
	resp, err := contractCaller.GetStateInfoById(opts, id.BigInt())
	if isErrIdentityDoesNotExist(err) {
		return nil, errIdentityDoesNotExist
	} else if err != nil {
		return nil, err
	}

	if resp.State == nil {
		return nil, errors.New("got empty state")
	}

	return merkletree.NewHashFromBigInt(resp.State)
}

func getEthClientForDID(did *w3c.DID, ethClients map[core.ChainID]*ethclient.Client) (*ethclient.Client, error) {
	chainID, err := core.ChainIDfromDID(*did)
	if err != nil {
		return nil, err
	}

	ethClient, ok := ethClients[chainID]
	if !ok {
		return nil, errors.Errorf("chain id is not registered for network '%d'", chainID)
	}
	return ethClient, nil
}

func getStateContractForDID(did *w3c.DID, stateContracts map[core.ChainID]common.Address) (out common.Address, err error) {
	chainID, err := core.ChainIDfromDID(*did)
	if err != nil {
		return out, err
	}

	contractAddr, ok := stateContracts[chainID]
	if !ok {
		return out, errors.Errorf("chain id is not registered for network '%d'", chainID)
	}
	return contractAddr, nil
}

func toRevocationStatus(status onchainABI.IOnchainCredentialStatusResolverCredentialStatus) (out verifiable.RevocationStatus, err error) {
	var existence bool
	var nodeAux *merkletree.NodeAux

	if status.Mtp.Existence {
		existence = true
	} else {
		existence = false
		if status.Mtp.AuxExistence {
			nodeAux = &merkletree.NodeAux{}
			nodeAux.Key, err = merkletree.NewHashFromBigInt(status.Mtp.AuxIndex)
			if err != nil {
				return out, errors.New("aux index is not a number")
			}
			nodeAux.Value, err = merkletree.NewHashFromBigInt(status.Mtp.AuxValue)
			if err != nil {
				return out, errors.New("aux value is not a number")
			}
		}
	}

	depth := calculateDepth(status.Mtp.Siblings)
	allSiblings := make([]*merkletree.Hash, depth)
	for i := 0; i < depth; i++ {
		sh, err := merkletree.NewHashFromBigInt(status.Mtp.Siblings[i])
		if err != nil {
			return out, errors.New("sibling is not a number")
		}
		allSiblings[i] = sh
	}

	proof, err := merkletree.NewProofFromData(existence, allSiblings, nodeAux)
	if err != nil {
		return out, errors.New("failed to create proof")
	}

	state, err := merkletree.NewHashFromBigInt(status.Issuer.State)
	if err != nil {
		return out, errors.New("state is not a number")
	}

	claimsRoot, err := merkletree.NewHashFromBigInt(status.Issuer.ClaimsTreeRoot)
	if err != nil {
		return out, errors.New("claims tree root is not a number")
	}

	revocationRoot, err := merkletree.NewHashFromBigInt(status.Issuer.RevocationTreeRoot)
	if err != nil {
		return out, errors.New("revocation tree root is not a number")
	}

	rootOfRoots, err := merkletree.NewHashFromBigInt(status.Issuer.RootOfRoots)
	if err != nil {
		return out, errors.New("root of roots tree root is not a number")
	}

	stateHex := state.Hex()
	claimsRootHex := claimsRoot.Hex()
	revocationRootHex := revocationRoot.Hex()
	rootOfRootsHex := rootOfRoots.Hex()

	return verifiable.RevocationStatus{
		MTP: *proof,
		Issuer: verifiable.TreeState{
			State:              &stateHex,
			ClaimsTreeRoot:     &claimsRootHex,
			RevocationTreeRoot: &revocationRootHex,
			RootOfRoots:        &rootOfRootsHex,
		},
	}, nil
}

func calculateDepth(siblings []*big.Int) int {
	for i := len(siblings) - 1; i >= 0; i-- {
		if siblings[i].Cmp(big.NewInt(0)) != 0 {
			return i + 1
		}
	}
	return 0
}

// function to fail a compilation if underlined type is not int32
func assertUnderlineTypeInt32[T ~int32](_ T) {}
