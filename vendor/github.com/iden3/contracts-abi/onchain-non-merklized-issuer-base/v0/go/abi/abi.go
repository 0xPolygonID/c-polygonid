// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package abi

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// INonMerklizedIssuerCredentialData is an auto generated low-level Go binding around an user-defined struct.
type INonMerklizedIssuerCredentialData struct {
	Id               *big.Int
	Context          []string
	Type             string
	IssuanceDate     uint64
	CredentialSchema INonMerklizedIssuerCredentialSchema
	DisplayMethod    INonMerklizedIssuerDisplayMethod
}

// INonMerklizedIssuerCredentialSchema is an auto generated low-level Go binding around an user-defined struct.
type INonMerklizedIssuerCredentialSchema struct {
	Id   string
	Type string
}

// INonMerklizedIssuerDisplayMethod is an auto generated low-level Go binding around an user-defined struct.
type INonMerklizedIssuerDisplayMethod struct {
	Id   string
	Type string
}

// INonMerklizedIssuerSubjectField is an auto generated low-level Go binding around an user-defined struct.
type INonMerklizedIssuerSubjectField struct {
	Key      string
	Value    *big.Int
	RawValue []byte
}

// IOnchainCredentialStatusResolverCredentialStatus is an auto generated low-level Go binding around an user-defined struct.
type IOnchainCredentialStatusResolverCredentialStatus struct {
	Issuer IOnchainCredentialStatusResolverIdentityStateRoots
	Mtp    IOnchainCredentialStatusResolverProof
}

// IOnchainCredentialStatusResolverIdentityStateRoots is an auto generated low-level Go binding around an user-defined struct.
type IOnchainCredentialStatusResolverIdentityStateRoots struct {
	State              *big.Int
	ClaimsTreeRoot     *big.Int
	RevocationTreeRoot *big.Int
	RootOfRoots        *big.Int
}

// IOnchainCredentialStatusResolverProof is an auto generated low-level Go binding around an user-defined struct.
type IOnchainCredentialStatusResolverProof struct {
	Root         *big.Int
	Existence    bool
	Siblings     []*big.Int
	Index        *big.Int
	Value        *big.Int
	AuxExistence bool
	AuxIndex     *big.Int
	AuxValue     *big.Int
}

// IdentityLibRoots is an auto generated low-level Go binding around an user-defined struct.
type IdentityLibRoots struct {
	ClaimsRoot      *big.Int
	RevocationsRoot *big.Int
	RootsRoot       *big.Int
}

// IdentityLibStateInfo is an auto generated low-level Go binding around an user-defined struct.
type IdentityLibStateInfo struct {
	State           *big.Int
	ClaimsRoot      *big.Int
	RevocationsRoot *big.Int
	RootsRoot       *big.Int
}

// SmtLibProof is an auto generated low-level Go binding around an user-defined struct.
type SmtLibProof struct {
	Root         *big.Int
	Existence    bool
	Siblings     []*big.Int
	Index        *big.Int
	Value        *big.Int
	AuxExistence bool
	AuxIndex     *big.Int
	AuxValue     *big.Int
}

// NonMerklizedIssuerBaseMetaData contains all meta data concerning the NonMerklizedIssuerBase contract.
var NonMerklizedIssuerBaseMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[],\"name\":\"CREDENTIAL_ADAPTER_VERSION\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"claimIndexHash\",\"type\":\"uint256\"}],\"name\":\"getClaimProof\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structSmtLib.Proof\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"claimIndexHash\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"}],\"name\":\"getClaimProofByRoot\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structSmtLib.Proof\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"claimIndexHash\",\"type\":\"uint256\"}],\"name\":\"getClaimProofWithStateInfo\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structSmtLib.Proof\",\"name\":\"\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"state\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"claimsRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"revocationsRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"rootsRoot\",\"type\":\"uint256\"}],\"internalType\":\"structIdentityLib.StateInfo\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getClaimsTreeRoot\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_userId\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"_credentialId\",\"type\":\"uint256\"}],\"name\":\"getCredential\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"id\",\"type\":\"uint256\"},{\"internalType\":\"string[]\",\"name\":\"context\",\"type\":\"string[]\"},{\"internalType\":\"string\",\"name\":\"_type\",\"type\":\"string\"},{\"internalType\":\"uint64\",\"name\":\"issuanceDate\",\"type\":\"uint64\"},{\"components\":[{\"internalType\":\"string\",\"name\":\"id\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"_type\",\"type\":\"string\"}],\"internalType\":\"structINonMerklizedIssuer.CredentialSchema\",\"name\":\"credentialSchema\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"string\",\"name\":\"id\",\"type\":\"string\"},{\"internalType\":\"string\",\"name\":\"_type\",\"type\":\"string\"}],\"internalType\":\"structINonMerklizedIssuer.DisplayMethod\",\"name\":\"displayMethod\",\"type\":\"tuple\"}],\"internalType\":\"structINonMerklizedIssuer.CredentialData\",\"name\":\"\",\"type\":\"tuple\"},{\"internalType\":\"uint256[8]\",\"name\":\"\",\"type\":\"uint256[8]\"},{\"components\":[{\"internalType\":\"string\",\"name\":\"key\",\"type\":\"string\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"rawValue\",\"type\":\"bytes\"}],\"internalType\":\"structINonMerklizedIssuer.SubjectField[]\",\"name\":\"\",\"type\":\"tuple[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getCredentialAdapterVersion\",\"outputs\":[{\"internalType\":\"string\",\"name\":\"\",\"type\":\"string\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getId\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getIsOldStateGenesis\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getLatestPublishedClaimsRoot\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getLatestPublishedRevocationsRoot\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getLatestPublishedRootsRoot\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getLatestPublishedState\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint64\",\"name\":\"revocationNonce\",\"type\":\"uint64\"}],\"name\":\"getRevocationProof\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structSmtLib.Proof\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint64\",\"name\":\"revocationNonce\",\"type\":\"uint64\"},{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"}],\"name\":\"getRevocationProofByRoot\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structSmtLib.Proof\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint64\",\"name\":\"revocationNonce\",\"type\":\"uint64\"}],\"name\":\"getRevocationProofWithStateInfo\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structSmtLib.Proof\",\"name\":\"\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"state\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"claimsRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"revocationsRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"rootsRoot\",\"type\":\"uint256\"}],\"internalType\":\"structIdentityLib.StateInfo\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"id\",\"type\":\"uint256\"},{\"internalType\":\"uint64\",\"name\":\"nonce\",\"type\":\"uint64\"}],\"name\":\"getRevocationStatus\",\"outputs\":[{\"components\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"state\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"claimsTreeRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"revocationTreeRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"rootOfRoots\",\"type\":\"uint256\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.IdentityStateRoots\",\"name\":\"issuer\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.Proof\",\"name\":\"mtp\",\"type\":\"tuple\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.CredentialStatus\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"id\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"state\",\"type\":\"uint256\"},{\"internalType\":\"uint64\",\"name\":\"nonce\",\"type\":\"uint64\"}],\"name\":\"getRevocationStatusByIdAndState\",\"outputs\":[{\"components\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"state\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"claimsTreeRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"revocationTreeRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"rootOfRoots\",\"type\":\"uint256\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.IdentityStateRoots\",\"name\":\"issuer\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.Proof\",\"name\":\"mtp\",\"type\":\"tuple\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.CredentialStatus\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getRevocationsTreeRoot\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"rootsTreeRoot\",\"type\":\"uint256\"}],\"name\":\"getRootProof\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structSmtLib.Proof\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"claimsTreeRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"}],\"name\":\"getRootProofByRoot\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structSmtLib.Proof\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"rootsTreeRoot\",\"type\":\"uint256\"}],\"name\":\"getRootProofWithStateInfo\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structSmtLib.Proof\",\"name\":\"\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"state\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"claimsRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"revocationsRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"rootsRoot\",\"type\":\"uint256\"}],\"internalType\":\"structIdentityLib.StateInfo\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"state\",\"type\":\"uint256\"}],\"name\":\"getRootsByState\",\"outputs\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"claimsRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"revocationsRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"rootsRoot\",\"type\":\"uint256\"}],\"internalType\":\"structIdentityLib.Roots\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getRootsTreeRoot\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"getSmtDepth\",\"outputs\":[{\"internalType\":\"uint256\",\"name\":\"\",\"type\":\"uint256\"}],\"stateMutability\":\"pure\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"_userId\",\"type\":\"uint256\"}],\"name\":\"getUserCredentialIds\",\"outputs\":[{\"internalType\":\"uint256[]\",\"name\":\"\",\"type\":\"uint256[]\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_stateContractAddr\",\"type\":\"address\"}],\"name\":\"initialize\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"bytes4\",\"name\":\"interfaceId\",\"type\":\"bytes4\"}],\"name\":\"supportsInterface\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

// NonMerklizedIssuerBaseABI is the input ABI used to generate the binding from.
// Deprecated: Use NonMerklizedIssuerBaseMetaData.ABI instead.
var NonMerklizedIssuerBaseABI = NonMerklizedIssuerBaseMetaData.ABI

// NonMerklizedIssuerBase is an auto generated Go binding around an Ethereum contract.
type NonMerklizedIssuerBase struct {
	NonMerklizedIssuerBaseCaller     // Read-only binding to the contract
	NonMerklizedIssuerBaseTransactor // Write-only binding to the contract
	NonMerklizedIssuerBaseFilterer   // Log filterer for contract events
}

// NonMerklizedIssuerBaseCaller is an auto generated read-only Go binding around an Ethereum contract.
type NonMerklizedIssuerBaseCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// NonMerklizedIssuerBaseTransactor is an auto generated write-only Go binding around an Ethereum contract.
type NonMerklizedIssuerBaseTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// NonMerklizedIssuerBaseFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type NonMerklizedIssuerBaseFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// NonMerklizedIssuerBaseSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type NonMerklizedIssuerBaseSession struct {
	Contract     *NonMerklizedIssuerBase // Generic contract binding to set the session for
	CallOpts     bind.CallOpts           // Call options to use throughout this session
	TransactOpts bind.TransactOpts       // Transaction auth options to use throughout this session
}

// NonMerklizedIssuerBaseCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type NonMerklizedIssuerBaseCallerSession struct {
	Contract *NonMerklizedIssuerBaseCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts                 // Call options to use throughout this session
}

// NonMerklizedIssuerBaseTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type NonMerklizedIssuerBaseTransactorSession struct {
	Contract     *NonMerklizedIssuerBaseTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts                 // Transaction auth options to use throughout this session
}

// NonMerklizedIssuerBaseRaw is an auto generated low-level Go binding around an Ethereum contract.
type NonMerklizedIssuerBaseRaw struct {
	Contract *NonMerklizedIssuerBase // Generic contract binding to access the raw methods on
}

// NonMerklizedIssuerBaseCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type NonMerklizedIssuerBaseCallerRaw struct {
	Contract *NonMerklizedIssuerBaseCaller // Generic read-only contract binding to access the raw methods on
}

// NonMerklizedIssuerBaseTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type NonMerklizedIssuerBaseTransactorRaw struct {
	Contract *NonMerklizedIssuerBaseTransactor // Generic write-only contract binding to access the raw methods on
}

// NewNonMerklizedIssuerBase creates a new instance of NonMerklizedIssuerBase, bound to a specific deployed contract.
func NewNonMerklizedIssuerBase(address common.Address, backend bind.ContractBackend) (*NonMerklizedIssuerBase, error) {
	contract, err := bindNonMerklizedIssuerBase(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &NonMerklizedIssuerBase{NonMerklizedIssuerBaseCaller: NonMerklizedIssuerBaseCaller{contract: contract}, NonMerklizedIssuerBaseTransactor: NonMerklizedIssuerBaseTransactor{contract: contract}, NonMerklizedIssuerBaseFilterer: NonMerklizedIssuerBaseFilterer{contract: contract}}, nil
}

// NewNonMerklizedIssuerBaseCaller creates a new read-only instance of NonMerklizedIssuerBase, bound to a specific deployed contract.
func NewNonMerklizedIssuerBaseCaller(address common.Address, caller bind.ContractCaller) (*NonMerklizedIssuerBaseCaller, error) {
	contract, err := bindNonMerklizedIssuerBase(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &NonMerklizedIssuerBaseCaller{contract: contract}, nil
}

// NewNonMerklizedIssuerBaseTransactor creates a new write-only instance of NonMerklizedIssuerBase, bound to a specific deployed contract.
func NewNonMerklizedIssuerBaseTransactor(address common.Address, transactor bind.ContractTransactor) (*NonMerklizedIssuerBaseTransactor, error) {
	contract, err := bindNonMerklizedIssuerBase(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &NonMerklizedIssuerBaseTransactor{contract: contract}, nil
}

// NewNonMerklizedIssuerBaseFilterer creates a new log filterer instance of NonMerklizedIssuerBase, bound to a specific deployed contract.
func NewNonMerklizedIssuerBaseFilterer(address common.Address, filterer bind.ContractFilterer) (*NonMerklizedIssuerBaseFilterer, error) {
	contract, err := bindNonMerklizedIssuerBase(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &NonMerklizedIssuerBaseFilterer{contract: contract}, nil
}

// bindNonMerklizedIssuerBase binds a generic wrapper to an already deployed contract.
func bindNonMerklizedIssuerBase(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := NonMerklizedIssuerBaseMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _NonMerklizedIssuerBase.Contract.NonMerklizedIssuerBaseCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _NonMerklizedIssuerBase.Contract.NonMerklizedIssuerBaseTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _NonMerklizedIssuerBase.Contract.NonMerklizedIssuerBaseTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _NonMerklizedIssuerBase.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _NonMerklizedIssuerBase.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _NonMerklizedIssuerBase.Contract.contract.Transact(opts, method, params...)
}

// CREDENTIALADAPTERVERSION is a free data retrieval call binding the contract method 0xde353972.
//
// Solidity: function CREDENTIAL_ADAPTER_VERSION() view returns(string)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) CREDENTIALADAPTERVERSION(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "CREDENTIAL_ADAPTER_VERSION")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// CREDENTIALADAPTERVERSION is a free data retrieval call binding the contract method 0xde353972.
//
// Solidity: function CREDENTIAL_ADAPTER_VERSION() view returns(string)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) CREDENTIALADAPTERVERSION() (string, error) {
	return _NonMerklizedIssuerBase.Contract.CREDENTIALADAPTERVERSION(&_NonMerklizedIssuerBase.CallOpts)
}

// CREDENTIALADAPTERVERSION is a free data retrieval call binding the contract method 0xde353972.
//
// Solidity: function CREDENTIAL_ADAPTER_VERSION() view returns(string)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) CREDENTIALADAPTERVERSION() (string, error) {
	return _NonMerklizedIssuerBase.Contract.CREDENTIALADAPTERVERSION(&_NonMerklizedIssuerBase.CallOpts)
}

// GetClaimProof is a free data retrieval call binding the contract method 0xb57a40cb.
//
// Solidity: function getClaimProof(uint256 claimIndexHash) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetClaimProof(opts *bind.CallOpts, claimIndexHash *big.Int) (SmtLibProof, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getClaimProof", claimIndexHash)

	if err != nil {
		return *new(SmtLibProof), err
	}

	out0 := *abi.ConvertType(out[0], new(SmtLibProof)).(*SmtLibProof)

	return out0, err

}

// GetClaimProof is a free data retrieval call binding the contract method 0xb57a40cb.
//
// Solidity: function getClaimProof(uint256 claimIndexHash) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetClaimProof(claimIndexHash *big.Int) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetClaimProof(&_NonMerklizedIssuerBase.CallOpts, claimIndexHash)
}

// GetClaimProof is a free data retrieval call binding the contract method 0xb57a40cb.
//
// Solidity: function getClaimProof(uint256 claimIndexHash) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetClaimProof(claimIndexHash *big.Int) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetClaimProof(&_NonMerklizedIssuerBase.CallOpts, claimIndexHash)
}

// GetClaimProofByRoot is a free data retrieval call binding the contract method 0x310d0d5b.
//
// Solidity: function getClaimProofByRoot(uint256 claimIndexHash, uint256 root) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetClaimProofByRoot(opts *bind.CallOpts, claimIndexHash *big.Int, root *big.Int) (SmtLibProof, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getClaimProofByRoot", claimIndexHash, root)

	if err != nil {
		return *new(SmtLibProof), err
	}

	out0 := *abi.ConvertType(out[0], new(SmtLibProof)).(*SmtLibProof)

	return out0, err

}

// GetClaimProofByRoot is a free data retrieval call binding the contract method 0x310d0d5b.
//
// Solidity: function getClaimProofByRoot(uint256 claimIndexHash, uint256 root) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetClaimProofByRoot(claimIndexHash *big.Int, root *big.Int) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetClaimProofByRoot(&_NonMerklizedIssuerBase.CallOpts, claimIndexHash, root)
}

// GetClaimProofByRoot is a free data retrieval call binding the contract method 0x310d0d5b.
//
// Solidity: function getClaimProofByRoot(uint256 claimIndexHash, uint256 root) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetClaimProofByRoot(claimIndexHash *big.Int, root *big.Int) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetClaimProofByRoot(&_NonMerklizedIssuerBase.CallOpts, claimIndexHash, root)
}

// GetClaimProofWithStateInfo is a free data retrieval call binding the contract method 0xb37feda4.
//
// Solidity: function getClaimProofWithStateInfo(uint256 claimIndexHash) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256), (uint256,uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetClaimProofWithStateInfo(opts *bind.CallOpts, claimIndexHash *big.Int) (SmtLibProof, IdentityLibStateInfo, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getClaimProofWithStateInfo", claimIndexHash)

	if err != nil {
		return *new(SmtLibProof), *new(IdentityLibStateInfo), err
	}

	out0 := *abi.ConvertType(out[0], new(SmtLibProof)).(*SmtLibProof)
	out1 := *abi.ConvertType(out[1], new(IdentityLibStateInfo)).(*IdentityLibStateInfo)

	return out0, out1, err

}

// GetClaimProofWithStateInfo is a free data retrieval call binding the contract method 0xb37feda4.
//
// Solidity: function getClaimProofWithStateInfo(uint256 claimIndexHash) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256), (uint256,uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetClaimProofWithStateInfo(claimIndexHash *big.Int) (SmtLibProof, IdentityLibStateInfo, error) {
	return _NonMerklizedIssuerBase.Contract.GetClaimProofWithStateInfo(&_NonMerklizedIssuerBase.CallOpts, claimIndexHash)
}

// GetClaimProofWithStateInfo is a free data retrieval call binding the contract method 0xb37feda4.
//
// Solidity: function getClaimProofWithStateInfo(uint256 claimIndexHash) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256), (uint256,uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetClaimProofWithStateInfo(claimIndexHash *big.Int) (SmtLibProof, IdentityLibStateInfo, error) {
	return _NonMerklizedIssuerBase.Contract.GetClaimProofWithStateInfo(&_NonMerklizedIssuerBase.CallOpts, claimIndexHash)
}

// GetClaimsTreeRoot is a free data retrieval call binding the contract method 0x3df432fc.
//
// Solidity: function getClaimsTreeRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetClaimsTreeRoot(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getClaimsTreeRoot")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetClaimsTreeRoot is a free data retrieval call binding the contract method 0x3df432fc.
//
// Solidity: function getClaimsTreeRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetClaimsTreeRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetClaimsTreeRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetClaimsTreeRoot is a free data retrieval call binding the contract method 0x3df432fc.
//
// Solidity: function getClaimsTreeRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetClaimsTreeRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetClaimsTreeRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetCredential is a free data retrieval call binding the contract method 0x37c1d9ff.
//
// Solidity: function getCredential(uint256 _userId, uint256 _credentialId) view returns((uint256,string[],string,uint64,(string,string),(string,string)), uint256[8], (string,uint256,bytes)[])
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetCredential(opts *bind.CallOpts, _userId *big.Int, _credentialId *big.Int) (INonMerklizedIssuerCredentialData, [8]*big.Int, []INonMerklizedIssuerSubjectField, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getCredential", _userId, _credentialId)

	if err != nil {
		return *new(INonMerklizedIssuerCredentialData), *new([8]*big.Int), *new([]INonMerklizedIssuerSubjectField), err
	}

	out0 := *abi.ConvertType(out[0], new(INonMerklizedIssuerCredentialData)).(*INonMerklizedIssuerCredentialData)
	out1 := *abi.ConvertType(out[1], new([8]*big.Int)).(*[8]*big.Int)
	out2 := *abi.ConvertType(out[2], new([]INonMerklizedIssuerSubjectField)).(*[]INonMerklizedIssuerSubjectField)

	return out0, out1, out2, err

}

// GetCredential is a free data retrieval call binding the contract method 0x37c1d9ff.
//
// Solidity: function getCredential(uint256 _userId, uint256 _credentialId) view returns((uint256,string[],string,uint64,(string,string),(string,string)), uint256[8], (string,uint256,bytes)[])
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetCredential(_userId *big.Int, _credentialId *big.Int) (INonMerklizedIssuerCredentialData, [8]*big.Int, []INonMerklizedIssuerSubjectField, error) {
	return _NonMerklizedIssuerBase.Contract.GetCredential(&_NonMerklizedIssuerBase.CallOpts, _userId, _credentialId)
}

// GetCredential is a free data retrieval call binding the contract method 0x37c1d9ff.
//
// Solidity: function getCredential(uint256 _userId, uint256 _credentialId) view returns((uint256,string[],string,uint64,(string,string),(string,string)), uint256[8], (string,uint256,bytes)[])
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetCredential(_userId *big.Int, _credentialId *big.Int) (INonMerklizedIssuerCredentialData, [8]*big.Int, []INonMerklizedIssuerSubjectField, error) {
	return _NonMerklizedIssuerBase.Contract.GetCredential(&_NonMerklizedIssuerBase.CallOpts, _userId, _credentialId)
}

// GetCredentialAdapterVersion is a free data retrieval call binding the contract method 0x09cb9b62.
//
// Solidity: function getCredentialAdapterVersion() pure returns(string)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetCredentialAdapterVersion(opts *bind.CallOpts) (string, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getCredentialAdapterVersion")

	if err != nil {
		return *new(string), err
	}

	out0 := *abi.ConvertType(out[0], new(string)).(*string)

	return out0, err

}

// GetCredentialAdapterVersion is a free data retrieval call binding the contract method 0x09cb9b62.
//
// Solidity: function getCredentialAdapterVersion() pure returns(string)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetCredentialAdapterVersion() (string, error) {
	return _NonMerklizedIssuerBase.Contract.GetCredentialAdapterVersion(&_NonMerklizedIssuerBase.CallOpts)
}

// GetCredentialAdapterVersion is a free data retrieval call binding the contract method 0x09cb9b62.
//
// Solidity: function getCredentialAdapterVersion() pure returns(string)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetCredentialAdapterVersion() (string, error) {
	return _NonMerklizedIssuerBase.Contract.GetCredentialAdapterVersion(&_NonMerklizedIssuerBase.CallOpts)
}

// GetId is a free data retrieval call binding the contract method 0x5d1ca631.
//
// Solidity: function getId() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetId(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getId")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetId is a free data retrieval call binding the contract method 0x5d1ca631.
//
// Solidity: function getId() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetId() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetId(&_NonMerklizedIssuerBase.CallOpts)
}

// GetId is a free data retrieval call binding the contract method 0x5d1ca631.
//
// Solidity: function getId() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetId() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetId(&_NonMerklizedIssuerBase.CallOpts)
}

// GetIsOldStateGenesis is a free data retrieval call binding the contract method 0xf84c7c1e.
//
// Solidity: function getIsOldStateGenesis() view returns(bool)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetIsOldStateGenesis(opts *bind.CallOpts) (bool, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getIsOldStateGenesis")

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// GetIsOldStateGenesis is a free data retrieval call binding the contract method 0xf84c7c1e.
//
// Solidity: function getIsOldStateGenesis() view returns(bool)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetIsOldStateGenesis() (bool, error) {
	return _NonMerklizedIssuerBase.Contract.GetIsOldStateGenesis(&_NonMerklizedIssuerBase.CallOpts)
}

// GetIsOldStateGenesis is a free data retrieval call binding the contract method 0xf84c7c1e.
//
// Solidity: function getIsOldStateGenesis() view returns(bool)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetIsOldStateGenesis() (bool, error) {
	return _NonMerklizedIssuerBase.Contract.GetIsOldStateGenesis(&_NonMerklizedIssuerBase.CallOpts)
}

// GetLatestPublishedClaimsRoot is a free data retrieval call binding the contract method 0x523b8136.
//
// Solidity: function getLatestPublishedClaimsRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetLatestPublishedClaimsRoot(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getLatestPublishedClaimsRoot")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetLatestPublishedClaimsRoot is a free data retrieval call binding the contract method 0x523b8136.
//
// Solidity: function getLatestPublishedClaimsRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetLatestPublishedClaimsRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetLatestPublishedClaimsRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetLatestPublishedClaimsRoot is a free data retrieval call binding the contract method 0x523b8136.
//
// Solidity: function getLatestPublishedClaimsRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetLatestPublishedClaimsRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetLatestPublishedClaimsRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetLatestPublishedRevocationsRoot is a free data retrieval call binding the contract method 0x9674cfa4.
//
// Solidity: function getLatestPublishedRevocationsRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetLatestPublishedRevocationsRoot(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getLatestPublishedRevocationsRoot")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetLatestPublishedRevocationsRoot is a free data retrieval call binding the contract method 0x9674cfa4.
//
// Solidity: function getLatestPublishedRevocationsRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetLatestPublishedRevocationsRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetLatestPublishedRevocationsRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetLatestPublishedRevocationsRoot is a free data retrieval call binding the contract method 0x9674cfa4.
//
// Solidity: function getLatestPublishedRevocationsRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetLatestPublishedRevocationsRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetLatestPublishedRevocationsRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetLatestPublishedRootsRoot is a free data retrieval call binding the contract method 0xc6365a3b.
//
// Solidity: function getLatestPublishedRootsRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetLatestPublishedRootsRoot(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getLatestPublishedRootsRoot")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetLatestPublishedRootsRoot is a free data retrieval call binding the contract method 0xc6365a3b.
//
// Solidity: function getLatestPublishedRootsRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetLatestPublishedRootsRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetLatestPublishedRootsRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetLatestPublishedRootsRoot is a free data retrieval call binding the contract method 0xc6365a3b.
//
// Solidity: function getLatestPublishedRootsRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetLatestPublishedRootsRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetLatestPublishedRootsRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetLatestPublishedState is a free data retrieval call binding the contract method 0x3d59ec60.
//
// Solidity: function getLatestPublishedState() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetLatestPublishedState(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getLatestPublishedState")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetLatestPublishedState is a free data retrieval call binding the contract method 0x3d59ec60.
//
// Solidity: function getLatestPublishedState() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetLatestPublishedState() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetLatestPublishedState(&_NonMerklizedIssuerBase.CallOpts)
}

// GetLatestPublishedState is a free data retrieval call binding the contract method 0x3d59ec60.
//
// Solidity: function getLatestPublishedState() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetLatestPublishedState() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetLatestPublishedState(&_NonMerklizedIssuerBase.CallOpts)
}

// GetRevocationProof is a free data retrieval call binding the contract method 0x26485063.
//
// Solidity: function getRevocationProof(uint64 revocationNonce) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetRevocationProof(opts *bind.CallOpts, revocationNonce uint64) (SmtLibProof, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getRevocationProof", revocationNonce)

	if err != nil {
		return *new(SmtLibProof), err
	}

	out0 := *abi.ConvertType(out[0], new(SmtLibProof)).(*SmtLibProof)

	return out0, err

}

// GetRevocationProof is a free data retrieval call binding the contract method 0x26485063.
//
// Solidity: function getRevocationProof(uint64 revocationNonce) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetRevocationProof(revocationNonce uint64) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationProof(&_NonMerklizedIssuerBase.CallOpts, revocationNonce)
}

// GetRevocationProof is a free data retrieval call binding the contract method 0x26485063.
//
// Solidity: function getRevocationProof(uint64 revocationNonce) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetRevocationProof(revocationNonce uint64) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationProof(&_NonMerklizedIssuerBase.CallOpts, revocationNonce)
}

// GetRevocationProofByRoot is a free data retrieval call binding the contract method 0xe26ecb0b.
//
// Solidity: function getRevocationProofByRoot(uint64 revocationNonce, uint256 root) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetRevocationProofByRoot(opts *bind.CallOpts, revocationNonce uint64, root *big.Int) (SmtLibProof, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getRevocationProofByRoot", revocationNonce, root)

	if err != nil {
		return *new(SmtLibProof), err
	}

	out0 := *abi.ConvertType(out[0], new(SmtLibProof)).(*SmtLibProof)

	return out0, err

}

// GetRevocationProofByRoot is a free data retrieval call binding the contract method 0xe26ecb0b.
//
// Solidity: function getRevocationProofByRoot(uint64 revocationNonce, uint256 root) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetRevocationProofByRoot(revocationNonce uint64, root *big.Int) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationProofByRoot(&_NonMerklizedIssuerBase.CallOpts, revocationNonce, root)
}

// GetRevocationProofByRoot is a free data retrieval call binding the contract method 0xe26ecb0b.
//
// Solidity: function getRevocationProofByRoot(uint64 revocationNonce, uint256 root) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetRevocationProofByRoot(revocationNonce uint64, root *big.Int) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationProofByRoot(&_NonMerklizedIssuerBase.CallOpts, revocationNonce, root)
}

// GetRevocationProofWithStateInfo is a free data retrieval call binding the contract method 0x0033058d.
//
// Solidity: function getRevocationProofWithStateInfo(uint64 revocationNonce) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256), (uint256,uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetRevocationProofWithStateInfo(opts *bind.CallOpts, revocationNonce uint64) (SmtLibProof, IdentityLibStateInfo, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getRevocationProofWithStateInfo", revocationNonce)

	if err != nil {
		return *new(SmtLibProof), *new(IdentityLibStateInfo), err
	}

	out0 := *abi.ConvertType(out[0], new(SmtLibProof)).(*SmtLibProof)
	out1 := *abi.ConvertType(out[1], new(IdentityLibStateInfo)).(*IdentityLibStateInfo)

	return out0, out1, err

}

// GetRevocationProofWithStateInfo is a free data retrieval call binding the contract method 0x0033058d.
//
// Solidity: function getRevocationProofWithStateInfo(uint64 revocationNonce) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256), (uint256,uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetRevocationProofWithStateInfo(revocationNonce uint64) (SmtLibProof, IdentityLibStateInfo, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationProofWithStateInfo(&_NonMerklizedIssuerBase.CallOpts, revocationNonce)
}

// GetRevocationProofWithStateInfo is a free data retrieval call binding the contract method 0x0033058d.
//
// Solidity: function getRevocationProofWithStateInfo(uint64 revocationNonce) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256), (uint256,uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetRevocationProofWithStateInfo(revocationNonce uint64) (SmtLibProof, IdentityLibStateInfo, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationProofWithStateInfo(&_NonMerklizedIssuerBase.CallOpts, revocationNonce)
}

// GetRevocationStatus is a free data retrieval call binding the contract method 0x110c96a7.
//
// Solidity: function getRevocationStatus(uint256 id, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetRevocationStatus(opts *bind.CallOpts, id *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getRevocationStatus", id, nonce)

	if err != nil {
		return *new(IOnchainCredentialStatusResolverCredentialStatus), err
	}

	out0 := *abi.ConvertType(out[0], new(IOnchainCredentialStatusResolverCredentialStatus)).(*IOnchainCredentialStatusResolverCredentialStatus)

	return out0, err

}

// GetRevocationStatus is a free data retrieval call binding the contract method 0x110c96a7.
//
// Solidity: function getRevocationStatus(uint256 id, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetRevocationStatus(id *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationStatus(&_NonMerklizedIssuerBase.CallOpts, id, nonce)
}

// GetRevocationStatus is a free data retrieval call binding the contract method 0x110c96a7.
//
// Solidity: function getRevocationStatus(uint256 id, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetRevocationStatus(id *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationStatus(&_NonMerklizedIssuerBase.CallOpts, id, nonce)
}

// GetRevocationStatusByIdAndState is a free data retrieval call binding the contract method 0xaad72921.
//
// Solidity: function getRevocationStatusByIdAndState(uint256 id, uint256 state, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetRevocationStatusByIdAndState(opts *bind.CallOpts, id *big.Int, state *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getRevocationStatusByIdAndState", id, state, nonce)

	if err != nil {
		return *new(IOnchainCredentialStatusResolverCredentialStatus), err
	}

	out0 := *abi.ConvertType(out[0], new(IOnchainCredentialStatusResolverCredentialStatus)).(*IOnchainCredentialStatusResolverCredentialStatus)

	return out0, err

}

// GetRevocationStatusByIdAndState is a free data retrieval call binding the contract method 0xaad72921.
//
// Solidity: function getRevocationStatusByIdAndState(uint256 id, uint256 state, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetRevocationStatusByIdAndState(id *big.Int, state *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationStatusByIdAndState(&_NonMerklizedIssuerBase.CallOpts, id, state, nonce)
}

// GetRevocationStatusByIdAndState is a free data retrieval call binding the contract method 0xaad72921.
//
// Solidity: function getRevocationStatusByIdAndState(uint256 id, uint256 state, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetRevocationStatusByIdAndState(id *big.Int, state *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationStatusByIdAndState(&_NonMerklizedIssuerBase.CallOpts, id, state, nonce)
}

// GetRevocationsTreeRoot is a free data retrieval call binding the contract method 0x01c85c77.
//
// Solidity: function getRevocationsTreeRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetRevocationsTreeRoot(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getRevocationsTreeRoot")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetRevocationsTreeRoot is a free data retrieval call binding the contract method 0x01c85c77.
//
// Solidity: function getRevocationsTreeRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetRevocationsTreeRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationsTreeRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetRevocationsTreeRoot is a free data retrieval call binding the contract method 0x01c85c77.
//
// Solidity: function getRevocationsTreeRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetRevocationsTreeRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetRevocationsTreeRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetRootProof is a free data retrieval call binding the contract method 0xc1e32733.
//
// Solidity: function getRootProof(uint256 rootsTreeRoot) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetRootProof(opts *bind.CallOpts, rootsTreeRoot *big.Int) (SmtLibProof, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getRootProof", rootsTreeRoot)

	if err != nil {
		return *new(SmtLibProof), err
	}

	out0 := *abi.ConvertType(out[0], new(SmtLibProof)).(*SmtLibProof)

	return out0, err

}

// GetRootProof is a free data retrieval call binding the contract method 0xc1e32733.
//
// Solidity: function getRootProof(uint256 rootsTreeRoot) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetRootProof(rootsTreeRoot *big.Int) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetRootProof(&_NonMerklizedIssuerBase.CallOpts, rootsTreeRoot)
}

// GetRootProof is a free data retrieval call binding the contract method 0xc1e32733.
//
// Solidity: function getRootProof(uint256 rootsTreeRoot) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetRootProof(rootsTreeRoot *big.Int) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetRootProof(&_NonMerklizedIssuerBase.CallOpts, rootsTreeRoot)
}

// GetRootProofByRoot is a free data retrieval call binding the contract method 0x2d5c4f25.
//
// Solidity: function getRootProofByRoot(uint256 claimsTreeRoot, uint256 root) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetRootProofByRoot(opts *bind.CallOpts, claimsTreeRoot *big.Int, root *big.Int) (SmtLibProof, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getRootProofByRoot", claimsTreeRoot, root)

	if err != nil {
		return *new(SmtLibProof), err
	}

	out0 := *abi.ConvertType(out[0], new(SmtLibProof)).(*SmtLibProof)

	return out0, err

}

// GetRootProofByRoot is a free data retrieval call binding the contract method 0x2d5c4f25.
//
// Solidity: function getRootProofByRoot(uint256 claimsTreeRoot, uint256 root) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetRootProofByRoot(claimsTreeRoot *big.Int, root *big.Int) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetRootProofByRoot(&_NonMerklizedIssuerBase.CallOpts, claimsTreeRoot, root)
}

// GetRootProofByRoot is a free data retrieval call binding the contract method 0x2d5c4f25.
//
// Solidity: function getRootProofByRoot(uint256 claimsTreeRoot, uint256 root) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetRootProofByRoot(claimsTreeRoot *big.Int, root *big.Int) (SmtLibProof, error) {
	return _NonMerklizedIssuerBase.Contract.GetRootProofByRoot(&_NonMerklizedIssuerBase.CallOpts, claimsTreeRoot, root)
}

// GetRootProofWithStateInfo is a free data retrieval call binding the contract method 0x443d7534.
//
// Solidity: function getRootProofWithStateInfo(uint256 rootsTreeRoot) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256), (uint256,uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetRootProofWithStateInfo(opts *bind.CallOpts, rootsTreeRoot *big.Int) (SmtLibProof, IdentityLibStateInfo, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getRootProofWithStateInfo", rootsTreeRoot)

	if err != nil {
		return *new(SmtLibProof), *new(IdentityLibStateInfo), err
	}

	out0 := *abi.ConvertType(out[0], new(SmtLibProof)).(*SmtLibProof)
	out1 := *abi.ConvertType(out[1], new(IdentityLibStateInfo)).(*IdentityLibStateInfo)

	return out0, out1, err

}

// GetRootProofWithStateInfo is a free data retrieval call binding the contract method 0x443d7534.
//
// Solidity: function getRootProofWithStateInfo(uint256 rootsTreeRoot) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256), (uint256,uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetRootProofWithStateInfo(rootsTreeRoot *big.Int) (SmtLibProof, IdentityLibStateInfo, error) {
	return _NonMerklizedIssuerBase.Contract.GetRootProofWithStateInfo(&_NonMerklizedIssuerBase.CallOpts, rootsTreeRoot)
}

// GetRootProofWithStateInfo is a free data retrieval call binding the contract method 0x443d7534.
//
// Solidity: function getRootProofWithStateInfo(uint256 rootsTreeRoot) view returns((uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256), (uint256,uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetRootProofWithStateInfo(rootsTreeRoot *big.Int) (SmtLibProof, IdentityLibStateInfo, error) {
	return _NonMerklizedIssuerBase.Contract.GetRootProofWithStateInfo(&_NonMerklizedIssuerBase.CallOpts, rootsTreeRoot)
}

// GetRootsByState is a free data retrieval call binding the contract method 0xb8db6871.
//
// Solidity: function getRootsByState(uint256 state) view returns((uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetRootsByState(opts *bind.CallOpts, state *big.Int) (IdentityLibRoots, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getRootsByState", state)

	if err != nil {
		return *new(IdentityLibRoots), err
	}

	out0 := *abi.ConvertType(out[0], new(IdentityLibRoots)).(*IdentityLibRoots)

	return out0, err

}

// GetRootsByState is a free data retrieval call binding the contract method 0xb8db6871.
//
// Solidity: function getRootsByState(uint256 state) view returns((uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetRootsByState(state *big.Int) (IdentityLibRoots, error) {
	return _NonMerklizedIssuerBase.Contract.GetRootsByState(&_NonMerklizedIssuerBase.CallOpts, state)
}

// GetRootsByState is a free data retrieval call binding the contract method 0xb8db6871.
//
// Solidity: function getRootsByState(uint256 state) view returns((uint256,uint256,uint256))
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetRootsByState(state *big.Int) (IdentityLibRoots, error) {
	return _NonMerklizedIssuerBase.Contract.GetRootsByState(&_NonMerklizedIssuerBase.CallOpts, state)
}

// GetRootsTreeRoot is a free data retrieval call binding the contract method 0xda68a0b1.
//
// Solidity: function getRootsTreeRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetRootsTreeRoot(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getRootsTreeRoot")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetRootsTreeRoot is a free data retrieval call binding the contract method 0xda68a0b1.
//
// Solidity: function getRootsTreeRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetRootsTreeRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetRootsTreeRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetRootsTreeRoot is a free data retrieval call binding the contract method 0xda68a0b1.
//
// Solidity: function getRootsTreeRoot() view returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetRootsTreeRoot() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetRootsTreeRoot(&_NonMerklizedIssuerBase.CallOpts)
}

// GetSmtDepth is a free data retrieval call binding the contract method 0x3f0c6648.
//
// Solidity: function getSmtDepth() pure returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetSmtDepth(opts *bind.CallOpts) (*big.Int, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getSmtDepth")

	if err != nil {
		return *new(*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new(*big.Int)).(**big.Int)

	return out0, err

}

// GetSmtDepth is a free data retrieval call binding the contract method 0x3f0c6648.
//
// Solidity: function getSmtDepth() pure returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetSmtDepth() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetSmtDepth(&_NonMerklizedIssuerBase.CallOpts)
}

// GetSmtDepth is a free data retrieval call binding the contract method 0x3f0c6648.
//
// Solidity: function getSmtDepth() pure returns(uint256)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetSmtDepth() (*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetSmtDepth(&_NonMerklizedIssuerBase.CallOpts)
}

// GetUserCredentialIds is a free data retrieval call binding the contract method 0x668d0bd4.
//
// Solidity: function getUserCredentialIds(uint256 _userId) view returns(uint256[])
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) GetUserCredentialIds(opts *bind.CallOpts, _userId *big.Int) ([]*big.Int, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "getUserCredentialIds", _userId)

	if err != nil {
		return *new([]*big.Int), err
	}

	out0 := *abi.ConvertType(out[0], new([]*big.Int)).(*[]*big.Int)

	return out0, err

}

// GetUserCredentialIds is a free data retrieval call binding the contract method 0x668d0bd4.
//
// Solidity: function getUserCredentialIds(uint256 _userId) view returns(uint256[])
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) GetUserCredentialIds(_userId *big.Int) ([]*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetUserCredentialIds(&_NonMerklizedIssuerBase.CallOpts, _userId)
}

// GetUserCredentialIds is a free data retrieval call binding the contract method 0x668d0bd4.
//
// Solidity: function getUserCredentialIds(uint256 _userId) view returns(uint256[])
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) GetUserCredentialIds(_userId *big.Int) ([]*big.Int, error) {
	return _NonMerklizedIssuerBase.Contract.GetUserCredentialIds(&_NonMerklizedIssuerBase.CallOpts, _userId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCaller) SupportsInterface(opts *bind.CallOpts, interfaceId [4]byte) (bool, error) {
	var out []interface{}
	err := _NonMerklizedIssuerBase.contract.Call(opts, &out, "supportsInterface", interfaceId)

	if err != nil {
		return *new(bool), err
	}

	out0 := *abi.ConvertType(out[0], new(bool)).(*bool)

	return out0, err

}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _NonMerklizedIssuerBase.Contract.SupportsInterface(&_NonMerklizedIssuerBase.CallOpts, interfaceId)
}

// SupportsInterface is a free data retrieval call binding the contract method 0x01ffc9a7.
//
// Solidity: function supportsInterface(bytes4 interfaceId) view returns(bool)
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseCallerSession) SupportsInterface(interfaceId [4]byte) (bool, error) {
	return _NonMerklizedIssuerBase.Contract.SupportsInterface(&_NonMerklizedIssuerBase.CallOpts, interfaceId)
}

// Initialize is a paid mutator transaction binding the contract method 0xc4d66de8.
//
// Solidity: function initialize(address _stateContractAddr) returns()
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseTransactor) Initialize(opts *bind.TransactOpts, _stateContractAddr common.Address) (*types.Transaction, error) {
	return _NonMerklizedIssuerBase.contract.Transact(opts, "initialize", _stateContractAddr)
}

// Initialize is a paid mutator transaction binding the contract method 0xc4d66de8.
//
// Solidity: function initialize(address _stateContractAddr) returns()
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseSession) Initialize(_stateContractAddr common.Address) (*types.Transaction, error) {
	return _NonMerklizedIssuerBase.Contract.Initialize(&_NonMerklizedIssuerBase.TransactOpts, _stateContractAddr)
}

// Initialize is a paid mutator transaction binding the contract method 0xc4d66de8.
//
// Solidity: function initialize(address _stateContractAddr) returns()
func (_NonMerklizedIssuerBase *NonMerklizedIssuerBaseTransactorSession) Initialize(_stateContractAddr common.Address) (*types.Transaction, error) {
	return _NonMerklizedIssuerBase.Contract.Initialize(&_NonMerklizedIssuerBase.TransactOpts, _stateContractAddr)
}
