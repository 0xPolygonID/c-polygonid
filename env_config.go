package c_polygonid

import (
	"encoding/json"
	"fmt"
	"sync"

	"github.com/ethereum/go-ethereum/common"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-schema-processor/v2/loaders"
	"github.com/piprate/json-gold/ld"
)

type EnvConfig struct {
	DIDMethods     []MethodConfig
	ChainConfigs   PerChainConfig
	IPFSNodeURL    string
	IPFSGatewayURL string
	CacheDir       string

	// backward incompatible fields, it's an error to use them
	EthereumURL       string
	StateContractAddr string
}

var globalRegistrationLock sync.Mutex
var registeredDIDMethods sync.Map

// NewEnvConfigFromJSON returns empty config if input json is nil.
func NewEnvConfigFromJSON(in []byte) (EnvConfig, error) {
	var cfg EnvConfig
	if in == nil {
		return cfg, nil
	}

	var err error
	err = json.Unmarshal(in, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("unable to parse json config: %w", err)
	}

	if cfg.EthereumURL != "" {
		return cfg, fmt.Errorf(
			"ethereumUrl is deprecated, use chainConfigs instead")
	}

	if cfg.StateContractAddr != "" {
		return cfg, fmt.Errorf(
			"stateContractAddr is deprecated, use chainConfigs instead")
	}

	if len(cfg.DIDMethods) == 0 {
		return cfg, nil
	}

	err = registerDIDMethods(cfg.DIDMethods)
	if err != nil {
		return cfg, err
	}

	var zeroAddr common.Address
	for _, didMethod := range cfg.DIDMethods {
		chainIDCfg, ok := cfg.ChainConfigs[didMethod.ChainID]
		if !ok {
			return cfg, fmt.Errorf("no chain config found for chain ID %v",
				didMethod.ChainID)
		}
		if chainIDCfg.RPCUrl == "" {
			return cfg, fmt.Errorf("no RPC URL found for chain ID %v",
				didMethod.ChainID)
		}
		if chainIDCfg.StateContractAddr == zeroAddr {
			return cfg, fmt.Errorf(
				"no state contract address found for chain ID %v",
				didMethod.ChainID)
		}
	}

	return cfg, err
}

func registerDIDMethods(methodConfigs []MethodConfig) error {
	newMethodConfigs := make([]MethodConfig, 0, len(methodConfigs))

	for _, methodCfg := range methodConfigs {
		if _, ok := registeredDIDMethods.Load(methodCfg.Hash()); !ok {
			newMethodConfigs = append(newMethodConfigs, methodCfg)
		}
	}

	if len(newMethodConfigs) == 0 {
		return nil
	}

	globalRegistrationLock.Lock()
	defer globalRegistrationLock.Unlock()

	for _, methodCfg := range newMethodConfigs {
		chainIDi := chainIDToInt(methodCfg.ChainID)

		params := core.DIDMethodNetworkParams{
			Method:      methodCfg.MethodName,
			Blockchain:  methodCfg.Blockchain,
			Network:     methodCfg.NetworkID,
			NetworkFlag: methodCfg.NetworkFlag,
		}
		err := core.RegisterDIDMethodNetwork(params,
			core.WithChainID(chainIDi),
			core.WithDIDMethodByte(methodCfg.MethodByte))
		if err != nil {
			return fmt.Errorf(
				"can't register DID method %v, blockchain %v, network ID %v, "+
					"network flag: %x, method byte %v, chain ID %v: %w",
				methodCfg.MethodName, methodCfg.Blockchain, methodCfg.NetworkID,
				methodCfg.NetworkFlag, methodCfg.MethodByte,
				methodCfg.ChainID, err)
		}

		registeredDIDMethods.Store(methodCfg.Hash(), struct{}{})
	}

	return nil
}

func (cfg EnvConfig) documentLoader() ld.DocumentLoader {
	var ipfsNode loaders.IPFSClient
	if cfg.IPFSNodeURL != "" {
		ipfsNode = &ipfsCli{rpcURL: cfg.IPFSNodeURL}
	}
	var ipfsGatewayURL string
	if cfg.IPFSGatewayURL != "" {
		ipfsGatewayURL = cfg.IPFSGatewayURL
	}

	var opts []loaders.DocumentLoaderOption

	cacheEngine, err := newBadgerCacheEngine(
		withEmbeddedDocumentBytes(
			"https://www.w3.org/2018/credentials/v1",
			credentialsV1JsonLDBytes),
		withCacheDir(cfg.CacheDir))
	if err == nil {
		opts = append(opts, loaders.WithCacheEngine(cacheEngine))
	}

	return loaders.NewDocumentLoader(ipfsNode, ipfsGatewayURL, opts...)
}
