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

// OnchainCredentialStatusResolverMetaData contains all meta data concerning the OnchainCredentialStatusResolver contract.
var OnchainCredentialStatusResolverMetaData = &bind.MetaData{
	ABI: "[{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"id\",\"type\":\"uint256\"},{\"internalType\":\"uint64\",\"name\":\"nonce\",\"type\":\"uint64\"}],\"name\":\"getRevocationStatus\",\"outputs\":[{\"components\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"state\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"claimsTreeRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"revocationTreeRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"rootOfRoots\",\"type\":\"uint256\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.IdentityStateRoots\",\"name\":\"issuer\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.Proof\",\"name\":\"mtp\",\"type\":\"tuple\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.CredentialStatus\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"uint256\",\"name\":\"id\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"state\",\"type\":\"uint256\"},{\"internalType\":\"uint64\",\"name\":\"nonce\",\"type\":\"uint64\"}],\"name\":\"getRevocationStatusByIdAndState\",\"outputs\":[{\"components\":[{\"components\":[{\"internalType\":\"uint256\",\"name\":\"state\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"claimsTreeRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"revocationTreeRoot\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"rootOfRoots\",\"type\":\"uint256\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.IdentityStateRoots\",\"name\":\"issuer\",\"type\":\"tuple\"},{\"components\":[{\"internalType\":\"uint256\",\"name\":\"root\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"existence\",\"type\":\"bool\"},{\"internalType\":\"uint256[]\",\"name\":\"siblings\",\"type\":\"uint256[]\"},{\"internalType\":\"uint256\",\"name\":\"index\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"value\",\"type\":\"uint256\"},{\"internalType\":\"bool\",\"name\":\"auxExistence\",\"type\":\"bool\"},{\"internalType\":\"uint256\",\"name\":\"auxIndex\",\"type\":\"uint256\"},{\"internalType\":\"uint256\",\"name\":\"auxValue\",\"type\":\"uint256\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.Proof\",\"name\":\"mtp\",\"type\":\"tuple\"}],\"internalType\":\"structIOnchainCredentialStatusResolver.CredentialStatus\",\"name\":\"\",\"type\":\"tuple\"}],\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

// OnchainCredentialStatusResolverABI is the input ABI used to generate the binding from.
// Deprecated: Use OnchainCredentialStatusResolverMetaData.ABI instead.
var OnchainCredentialStatusResolverABI = OnchainCredentialStatusResolverMetaData.ABI

// OnchainCredentialStatusResolver is an auto generated Go binding around an Ethereum contract.
type OnchainCredentialStatusResolver struct {
	OnchainCredentialStatusResolverCaller     // Read-only binding to the contract
	OnchainCredentialStatusResolverTransactor // Write-only binding to the contract
	OnchainCredentialStatusResolverFilterer   // Log filterer for contract events
}

// OnchainCredentialStatusResolverCaller is an auto generated read-only Go binding around an Ethereum contract.
type OnchainCredentialStatusResolverCaller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OnchainCredentialStatusResolverTransactor is an auto generated write-only Go binding around an Ethereum contract.
type OnchainCredentialStatusResolverTransactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OnchainCredentialStatusResolverFilterer is an auto generated log filtering Go binding around an Ethereum contract events.
type OnchainCredentialStatusResolverFilterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// OnchainCredentialStatusResolverSession is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type OnchainCredentialStatusResolverSession struct {
	Contract     *OnchainCredentialStatusResolver // Generic contract binding to set the session for
	CallOpts     bind.CallOpts                    // Call options to use throughout this session
	TransactOpts bind.TransactOpts                // Transaction auth options to use throughout this session
}

// OnchainCredentialStatusResolverCallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type OnchainCredentialStatusResolverCallerSession struct {
	Contract *OnchainCredentialStatusResolverCaller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts                          // Call options to use throughout this session
}

// OnchainCredentialStatusResolverTransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type OnchainCredentialStatusResolverTransactorSession struct {
	Contract     *OnchainCredentialStatusResolverTransactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts                          // Transaction auth options to use throughout this session
}

// OnchainCredentialStatusResolverRaw is an auto generated low-level Go binding around an Ethereum contract.
type OnchainCredentialStatusResolverRaw struct {
	Contract *OnchainCredentialStatusResolver // Generic contract binding to access the raw methods on
}

// OnchainCredentialStatusResolverCallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type OnchainCredentialStatusResolverCallerRaw struct {
	Contract *OnchainCredentialStatusResolverCaller // Generic read-only contract binding to access the raw methods on
}

// OnchainCredentialStatusResolverTransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type OnchainCredentialStatusResolverTransactorRaw struct {
	Contract *OnchainCredentialStatusResolverTransactor // Generic write-only contract binding to access the raw methods on
}

// NewOnchainCredentialStatusResolver creates a new instance of OnchainCredentialStatusResolver, bound to a specific deployed contract.
func NewOnchainCredentialStatusResolver(address common.Address, backend bind.ContractBackend) (*OnchainCredentialStatusResolver, error) {
	contract, err := bindOnchainCredentialStatusResolver(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &OnchainCredentialStatusResolver{OnchainCredentialStatusResolverCaller: OnchainCredentialStatusResolverCaller{contract: contract}, OnchainCredentialStatusResolverTransactor: OnchainCredentialStatusResolverTransactor{contract: contract}, OnchainCredentialStatusResolverFilterer: OnchainCredentialStatusResolverFilterer{contract: contract}}, nil
}

// NewOnchainCredentialStatusResolverCaller creates a new read-only instance of OnchainCredentialStatusResolver, bound to a specific deployed contract.
func NewOnchainCredentialStatusResolverCaller(address common.Address, caller bind.ContractCaller) (*OnchainCredentialStatusResolverCaller, error) {
	contract, err := bindOnchainCredentialStatusResolver(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &OnchainCredentialStatusResolverCaller{contract: contract}, nil
}

// NewOnchainCredentialStatusResolverTransactor creates a new write-only instance of OnchainCredentialStatusResolver, bound to a specific deployed contract.
func NewOnchainCredentialStatusResolverTransactor(address common.Address, transactor bind.ContractTransactor) (*OnchainCredentialStatusResolverTransactor, error) {
	contract, err := bindOnchainCredentialStatusResolver(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &OnchainCredentialStatusResolverTransactor{contract: contract}, nil
}

// NewOnchainCredentialStatusResolverFilterer creates a new log filterer instance of OnchainCredentialStatusResolver, bound to a specific deployed contract.
func NewOnchainCredentialStatusResolverFilterer(address common.Address, filterer bind.ContractFilterer) (*OnchainCredentialStatusResolverFilterer, error) {
	contract, err := bindOnchainCredentialStatusResolver(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &OnchainCredentialStatusResolverFilterer{contract: contract}, nil
}

// bindOnchainCredentialStatusResolver binds a generic wrapper to an already deployed contract.
func bindOnchainCredentialStatusResolver(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := OnchainCredentialStatusResolverMetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _OnchainCredentialStatusResolver.Contract.OnchainCredentialStatusResolverCaller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _OnchainCredentialStatusResolver.Contract.OnchainCredentialStatusResolverTransactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _OnchainCredentialStatusResolver.Contract.OnchainCredentialStatusResolverTransactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverCallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _OnchainCredentialStatusResolver.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverTransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _OnchainCredentialStatusResolver.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverTransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _OnchainCredentialStatusResolver.Contract.contract.Transact(opts, method, params...)
}

// GetRevocationStatus is a free data retrieval call binding the contract method 0x110c96a7.
//
// Solidity: function getRevocationStatus(uint256 id, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverCaller) GetRevocationStatus(opts *bind.CallOpts, id *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	var out []interface{}
	err := _OnchainCredentialStatusResolver.contract.Call(opts, &out, "getRevocationStatus", id, nonce)

	if err != nil {
		return *new(IOnchainCredentialStatusResolverCredentialStatus), err
	}

	out0 := *abi.ConvertType(out[0], new(IOnchainCredentialStatusResolverCredentialStatus)).(*IOnchainCredentialStatusResolverCredentialStatus)

	return out0, err

}

// GetRevocationStatus is a free data retrieval call binding the contract method 0x110c96a7.
//
// Solidity: function getRevocationStatus(uint256 id, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverSession) GetRevocationStatus(id *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	return _OnchainCredentialStatusResolver.Contract.GetRevocationStatus(&_OnchainCredentialStatusResolver.CallOpts, id, nonce)
}

// GetRevocationStatus is a free data retrieval call binding the contract method 0x110c96a7.
//
// Solidity: function getRevocationStatus(uint256 id, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverCallerSession) GetRevocationStatus(id *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	return _OnchainCredentialStatusResolver.Contract.GetRevocationStatus(&_OnchainCredentialStatusResolver.CallOpts, id, nonce)
}

// GetRevocationStatusByIdAndState is a free data retrieval call binding the contract method 0xaad72921.
//
// Solidity: function getRevocationStatusByIdAndState(uint256 id, uint256 state, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverCaller) GetRevocationStatusByIdAndState(opts *bind.CallOpts, id *big.Int, state *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	var out []interface{}
	err := _OnchainCredentialStatusResolver.contract.Call(opts, &out, "getRevocationStatusByIdAndState", id, state, nonce)

	if err != nil {
		return *new(IOnchainCredentialStatusResolverCredentialStatus), err
	}

	out0 := *abi.ConvertType(out[0], new(IOnchainCredentialStatusResolverCredentialStatus)).(*IOnchainCredentialStatusResolverCredentialStatus)

	return out0, err

}

// GetRevocationStatusByIdAndState is a free data retrieval call binding the contract method 0xaad72921.
//
// Solidity: function getRevocationStatusByIdAndState(uint256 id, uint256 state, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverSession) GetRevocationStatusByIdAndState(id *big.Int, state *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	return _OnchainCredentialStatusResolver.Contract.GetRevocationStatusByIdAndState(&_OnchainCredentialStatusResolver.CallOpts, id, state, nonce)
}

// GetRevocationStatusByIdAndState is a free data retrieval call binding the contract method 0xaad72921.
//
// Solidity: function getRevocationStatusByIdAndState(uint256 id, uint256 state, uint64 nonce) view returns(((uint256,uint256,uint256,uint256),(uint256,bool,uint256[],uint256,uint256,bool,uint256,uint256)))
func (_OnchainCredentialStatusResolver *OnchainCredentialStatusResolverCallerSession) GetRevocationStatusByIdAndState(id *big.Int, state *big.Int, nonce uint64) (IOnchainCredentialStatusResolverCredentialStatus, error) {
	return _OnchainCredentialStatusResolver.Contract.GetRevocationStatusByIdAndState(&_OnchainCredentialStatusResolver.CallOpts, id, state, nonce)
}
