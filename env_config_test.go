package c_polygonid

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/stretchr/testify/require"
)

func TestNewEnvConfigFromJSON(t *testing.T) {
	cfgJSON := `{
  "ethereumUrl": "http://localhost:8545",
  "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655",
  "reverseHashServiceUrl": "http://localhost:8003",
  "ipfsNodeUrl": "http://localhost:5001",
  "chainConfigs": {
    "1": {
      "rpcUrl": "http://localhost:8545",
      "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"
    },
    "0x10": {
      "rpcUrl": "http://localhost:8546",
      "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"
    },
    "0X11": {
      "rpcUrl": "http://localhost:8547",
      "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"
    }
  },
  "didMethods": [
    {
      "name": "ethr",
      "blockchain": "ethereum",
      "network": "mainnet",
      "networkFlag": 6,
      "methodByte": "0b010011",
      "chainID": "10293"
    }
  ]
}`
	cfg, err := NewEnvConfigFromJSON([]byte(cfgJSON))
	require.NoError(t, err)

	require.Equal(t,
		EnvConfig{
			DIDMethods: []MethodConfig{
				{
					MethodName:  "ethr",
					Blockchain:  "ethereum",
					NetworkID:   "mainnet",
					NetworkFlag: 6,
					MethodByte:  19,
					ChainID:     10293,
				},
			},
			ChainConfigs: PerChainConfig{
				1: {
					RPCUrl:            "http://localhost:8545",
					StateContractAddr: common.HexToAddress("0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"),
				},
				16: {
					RPCUrl:            "http://localhost:8546",
					StateContractAddr: common.HexToAddress("0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"),
				},
				17: {
					RPCUrl:            "http://localhost:8547",
					StateContractAddr: common.HexToAddress("0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"),
				},
			},
			EthereumURL:           "http://localhost:8545",
			StateContractAddr:     common.HexToAddress("0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"),
			ReverseHashServiceUrl: "http://localhost:8003",
			IPFSNodeURL:           "http://localhost:5001",
		},
		cfg)

	// check that custom DID methods are registered
	chainID, err := core.GetChainID("ethereum", "mainnet")
	require.NoError(t, err)
	require.Equal(t, core.ChainID(10293), chainID)
	blockchain, networkID, err := core.NetworkByChainID(core.ChainID(10293))
	require.NoError(t, err)
	require.Equal(t, core.Blockchain("ethereum"), blockchain)
	require.Equal(t, core.NetworkID("mainnet"), networkID)
}
