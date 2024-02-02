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
	DIDMethods            []MethodConfig
	ChainConfigs          PerChainConfig
	EthereumURL           string         // Deprecated: Use ChainConfigs instead
	StateContractAddr     common.Address // Deprecated: Use ChainConfigs instead
	ReverseHashServiceUrl string         // Deprecated
	IPFSNodeURL           string
}

var globalRegistationLock sync.Mutex
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

	if len(cfg.ChainConfigs) == 0 {
		return cfg, nil
	}

	err = registerDIDMethods(cfg.DIDMethods)
	return cfg, err
}

func registerDIDMethods(methodConfigs []MethodConfig) error {
	newMethodConfigs := make([]MethodConfig, 0, len(methodConfigs))

	for _, methodCfg := range methodConfigs {
		err := methodCfg.validate()
		if err != nil {
			return fmt.Errorf("invalid method config: %w", err)
		}

		if _, ok := registeredDIDMethods.Load(methodCfg.Hash()); !ok {
			newMethodConfigs = append(newMethodConfigs, methodCfg)
		}
	}

	if len(newMethodConfigs) == 0 {
		return nil
	}

	globalRegistationLock.Lock()
	defer globalRegistationLock.Unlock()

	for _, methodCfg := range newMethodConfigs {
		chainIDi := chainIDToInt(*methodCfg.ChainID)

		params := core.DIDMethodNetworkParams{
			Method:      methodCfg.MethodName,
			Blockchain:  methodCfg.Blockchain,
			Network:     methodCfg.NetworkID,
			NetworkFlag: methodCfg.NetworkFlag.Byte(),
		}
		err := core.RegisterDIDMethodNetwork(params,
			core.WithChainID(chainIDi),
			core.WithDIDMethodByte(methodCfg.MethodByte.Byte()))
		if err != nil {
			return fmt.Errorf(
				"can't register DID method %v, blockchain %v, network ID %v, "+
					"network flag: %x, method byte %v, chain ID %v: %w",
				methodCfg.MethodName, methodCfg.Blockchain, methodCfg.NetworkID,
				*methodCfg.NetworkFlag, *methodCfg.MethodByte,
				*methodCfg.ChainID, err)
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

	var opts []loaders.DocumentLoaderOption

	cacheEngine, err := newBadgerCacheEngine(
		withEmbeddedDocumentBytes(
			"https://www.w3.org/2018/credentials/v1",
			credentialsV1JsonLDBytes))
	if err == nil {
		opts = append(opts, loaders.WithCacheEngine(cacheEngine))
	}

	return loaders.NewDocumentLoader(ipfsNode, "", opts...)
}
