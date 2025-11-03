package c_polygonid

import (
	"encoding/json"
	"testing"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/stretchr/testify/require"
)

func TestMethodConfig_UnmarshalJSON(t *testing.T) {
	in := `{
      "name": "ethr",
      "blockchain": "ethereum",
      "network": "mainnet",
      "networkFlag": 6,
      "methodByte": "0b010011",
      "chainID": "10293"
    }`
	var methodCfg MethodConfig
	err := json.Unmarshal([]byte(in), &methodCfg)
	require.NoError(t, err)

	require.Equal(t, core.DIDMethod("ethr"), methodCfg.MethodName)
	require.Equal(t, core.Blockchain("ethereum"), methodCfg.Blockchain)
	require.Equal(t, core.NetworkID("mainnet"), methodCfg.NetworkID)
	require.Equal(t, byte(6), methodCfg.NetworkFlag)
	require.Equal(t, byte(19), methodCfg.MethodByte)
	require.Equal(t, core.ChainID(10293), methodCfg.ChainID)

	in = `{
      "blockchain": "ethereum",
      "network": "mainnet",
      "networkFlag": 6,
      "methodByte": "0b010011",
      "chainID": "10293"
    }`
	err = json.Unmarshal([]byte(in), &methodCfg)
	require.EqualError(t, err, "method name is empty")

	in = `{
      "name": "ethr",
      "blockchain": "ethereum",
      "network": "mainnet",
      "networkFlag": 6,
      "methodByte": "0b010011",
      "chainID": "0X123"
    }`
	err = json.Unmarshal([]byte(in), &methodCfg)
	require.NoError(t, err)
	require.Equal(t, core.ChainID(291), methodCfg.ChainID)
}
