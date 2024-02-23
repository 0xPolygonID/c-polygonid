package c_polygonid

import (
	"context"
	"encoding/json"
	"testing"

	httpmock "github.com/0xPolygonID/c-polygonid/testing"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/stretchr/testify/require"
)

func TestW3CCredentialFromOnchainHex(t *testing.T) {
	defer mockBadgerLog(t)()

	doTest := func(t testing.TB, inFile, wantOutFile string, cfg EnvConfig) {
		ctx := context.Background()
		in := readFixtureFile(inFile)
		wantOut := readFixtureFile(wantOutFile)

		out, err := W3CCredentialFromOnchainHex(
			ctx,
			cfg,
			in,
		)
		require.NoError(t, err)

		var wantOutCredential *verifiable.W3CCredential
		err = json.Unmarshal(wantOut, &wantOutCredential)
		require.NoError(t, err)

		// since want verifiable credential was parsed from json,
		// there not are types for the fields
		outBytes, err := json.Marshal(out)
		require.NoError(t, err)
		var actualOutCredential *verifiable.W3CCredential
		err = json.Unmarshal(outBytes, &actualOutCredential)
		require.NoError(t, err)

		require.Equal(t, wantOutCredential, actualOutCredential)
	}

	removeIdFromEthBody := func(body []byte) []byte {
		var ethBody map[string]any
		err := json.Unmarshal(body, &ethBody)
		require.NoError(t, err)
		if stringFromJsonObj(ethBody, "jsonrpc") == "2.0" &&
			stringFromJsonObj(ethBody, "method") == "eth_call" {

			delete(ethBody, "id")
		}
		body, err = json.Marshal(ethBody)
		require.NoError(t, err)
		return body
	}

	t.Run("happy path", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t,
			map[string]string{
				`http://localhost:8545%%%{"jsonrpc":"2.0","method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0xb37feda415bbb043d40cadbd377aeb19ef410cd8adb55a41c63707a628fefa0fac2c3ba1","to":"0xc84e8ac5385e0813f01aa9c698ed44c831961670"},"latest"]}`: "testdata/httpresp_eth_mtp_proof_onchain_issuer.json",
				"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld": "testdata/httpresp_iden3proofs.jsonld",
				"https://gist.githubusercontent.com/ilya-korotya/660496c859f8d31a7d2a92ca5e970967/raw/6b5fc14fe630c17bfa52e05e08fdc8394c5ea0ce/non-merklized-non-zero-balance.jsonld": "testdata/httpresp_non-merklized-non-zero-balance.jsonld",
				"https://schema.iden3.io/core/jsonld/displayMethod.jsonld": "testdata/httpresp_displayMethod.jsonld",
			},
			httpmock.IgnoreUntouchedURLs(),
			httpmock.WithPostRequestBodyProcessor(removeIdFromEthBody),
		)()
		cfg := EnvConfig{
			ChainConfigs: map[core.ChainID]ChainConfig{
				80001: {
					RPCUrl: "http://localhost:8545",
				},
			},
		}

		doTest(
			t,
			"w3c_credential_from_onchain_hex_input.json",
			"w3c_credential_from_onchain_hex_output.json",
			cfg,
		)
	})
}
