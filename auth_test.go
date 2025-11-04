package c_polygonid

import (
	"context"
	"fmt"
	"os"
	"testing"

	httpmock "github.com/0xPolygonID/c-polygonid/testing"
	"github.com/ethereum/go-ethereum/common"
	"github.com/iden3/go-iden3-auth/v2/pubsignals"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/stretchr/testify/require"
)

func TestVerifyAuthResponse_JWZFormat_Non_Empty_Request(t *testing.T) {
	ipfsURL := os.Getenv("IPFS_URL")
	if ipfsURL == "" {
		t.Fatal("IPFS_URL is not set")
	}

	fn := func(path string) string {
		return fmt.Sprintf("testdata/%s", path)
	}

	defer preserveIPFSHttpCli()()
	cid := uploadIPFSFile(t, ipfsURL, fn("liveness_credential.json-ld"))
	require.Equal(t, "QmcomGJQwJDCg3RE6FjsFYCjjMSTWJXY3fUWeq43Mc5CCJ", cid)

	in, err := os.ReadFile(fn("auth_response_with_options_jwz_format.json"))
	require.NoError(t, err)

	defer httpmock.MockHTTPClient(t,
		map[string]string{
			`https://localhost:8080%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x7c1a66de0000000000000000000000000000000000000000000000000000000000000000","to":"0x3c9acb2205aa72a05f6d77d708b5cf85fca3a896"},"latest"]}`:                                                                 fn("httpresp_eth_state_auth_input_0x7c1a66de0000000000000000000000000000000000000000000000000000000000000000.json"),
			`https://localhost:8080%%%{"jsonrpc":"2.0","id":2,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x53c87312000ce0114a0c3cdd02a4c5f0b761f51d51da5903ea12680b30e3c2c06b33b101114a0c3cdd02a4c5f0b761f51d51da5903ea12680b30e3c2c06b33d3792201c1","to":"0x3c9acb2205aa72a05f6d77d708b5cf85fca3a896"},"latest"]}`: fn("httpresp_eth_state_genesis_not_exist_0x53c87312000ce0114a0c3cdd02a4c5f0b761f51d51da5903ea12680b30e3c2c06b33b101114a0c3cdd02a4c5f0b761f51d51da5903ea12680b30e3c2c06b33d3792201c1.json"),
		},
		httpmock.IgnoreUntouchedURLs(),
	)()

	cfg := EnvConfig{
		ChainConfigs: map[core.ChainID]ChainConfig{
			45056: {
				RPCUrl:            "https://localhost:8080",
				StateContractAddr: common.HexToAddress("0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896"),
			},
		},
		IPFSNodeURL: ipfsURL,
	}

	b, err := VerifyAuthResponse(context.Background(), cfg, in)
	require.NoError(t, err)
	require.NotEmpty(t, b)
}

func TestVerifyAuthResponse_JWEFormat_Empty_Request(t *testing.T) {
	fn := func(path string) string {
		return fmt.Sprintf("testdata/%s", path)
	}

	in, err := os.ReadFile(fn("auth_response_with_options_jwe_format.json"))
	require.NoError(t, err)

	cfg := EnvConfig{
		ChainConfigs: map[core.ChainID]ChainConfig{
			45056: {
				RPCUrl:            "https://localhost:8080",
				StateContractAddr: common.HexToAddress("0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896"),
			},
		},
	}

	b, err := VerifyAuthResponse(context.Background(), cfg, in)
	require.NoError(t, err)
	require.NotEmpty(t, b)
}

func TestVerifyAuthResponse_JWEFormat_Non_Empty_Request(t *testing.T) {
	ipfsURL := os.Getenv("IPFS_URL")
	if ipfsURL == "" {
		t.Fatal("IPFS_URL is not set")
	}

	fn := func(path string) string {
		return fmt.Sprintf("testdata/%s", path)
	}

	defer preserveIPFSHttpCli()()
	cid := uploadIPFSFile(t, ipfsURL, fn("liveness_credential.json-ld"))
	require.Equal(t, "QmcomGJQwJDCg3RE6FjsFYCjjMSTWJXY3fUWeq43Mc5CCJ", cid)

	in, err := os.ReadFile(fn("auth_response_with_options_jwe_non_empty_request.json"))
	require.NoError(t, err)

	defer httpmock.MockHTTPClient(t,
		map[string]string{
			`https://localhost:8081%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x53c87312000e4309ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab78130109ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab788b7ea017ed","to":"0x1a4cc30f2aa0377b0c3bc9848766d90cb4404124"},"latest"]}`: fn("httpresp_polygon_amoy_0x53c87312000e4309ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab78130109ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab788b7ea017ed.json"),
			`https://localhost:8081%%%{"jsonrpc":"2.0","id":2,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x53c87312000e4309ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab78130115b8f79f299a51b57774d7bc3da79655dbeb670893d2f199f44ec0a4523e9622","to":"0x1a4cc30f2aa0377b0c3bc9848766d90cb4404124"},"latest"]}`: fn("httpresp_polygon_amoy_0x53c87312000e4309ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab78130115b8f79f299a51b57774d7bc3da79655dbeb670893d2f199f44ec0a4523e9622.json"),
		},
		httpmock.IgnoreUntouchedURLs(),
	)()

	cfg := EnvConfig{
		ChainConfigs: map[core.ChainID]ChainConfig{
			80002: {
				RPCUrl:            "https://localhost:8081",
				StateContractAddr: common.HexToAddress("0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124"),
			},
		},
		IPFSNodeURL: ipfsURL,
	}

	b, err := VerifyAuthResponse(context.Background(), cfg, in)
	require.NoError(t, err)
	require.NotEmpty(t, b)
}

func TestVerifyAuthResponse_PlainFormat_Non_Empty_Request(t *testing.T) {
	ipfsURL := os.Getenv("IPFS_URL")
	if ipfsURL == "" {
		t.Fatal("IPFS_URL is not set")
	}

	fn := func(path string) string {
		return fmt.Sprintf("testdata/%s", path)
	}

	defer preserveIPFSHttpCli()()
	cid := uploadIPFSFile(t, ipfsURL, fn("liveness_credential.json-ld"))
	require.Equal(t, "QmcomGJQwJDCg3RE6FjsFYCjjMSTWJXY3fUWeq43Mc5CCJ", cid)

	in, err := os.ReadFile(fn("auth_response_with_options_plain_text_non_empty_request.json"))
	require.NoError(t, err)

	defer httpmock.MockHTTPClient(t,
		map[string]string{
			`https://localhost:8081%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x53c87312000e4309ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab78130109ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab788b7ea017ed","to":"0x1a4cc30f2aa0377b0c3bc9848766d90cb4404124"},"latest"]}`: fn("httpresp_polygon_amoy_0x53c87312000e4309ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab78130109ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab788b7ea017ed.json"),
			`https://localhost:8081%%%{"jsonrpc":"2.0","id":2,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x53c87312000e4309ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab78130115b8f79f299a51b57774d7bc3da79655dbeb670893d2f199f44ec0a4523e9622","to":"0x1a4cc30f2aa0377b0c3bc9848766d90cb4404124"},"latest"]}`: fn("httpresp_polygon_amoy_0x53c87312000e4309ebc549d974a1c8de06d5146790a53c667ed3a49f82079597ab78130115b8f79f299a51b57774d7bc3da79655dbeb670893d2f199f44ec0a4523e9622.json"),
		},
		httpmock.IgnoreUntouchedURLs(),
	)()

	cfg := EnvConfig{
		ChainConfigs: map[core.ChainID]ChainConfig{
			80002: {
				RPCUrl:            "https://localhost:8081",
				StateContractAddr: common.HexToAddress("0x1a4cC30f2aA0377b0c3bc9848766D90cb4404124"),
			},
		},
		IPFSNodeURL: ipfsURL,
	}

	b, err := VerifyAuthResponse(context.Background(), cfg, in)
	require.NoError(t, err)
	require.NotEmpty(t, b)
}

func TestVerifyAuthResponse_Error_ProofIsOutdated(t *testing.T) {
	ipfsURL := os.Getenv("IPFS_URL")
	if ipfsURL == "" {
		t.Fatal("IPFS_URL is not set")
	}

	fn := func(path string) string {
		return fmt.Sprintf("testdata/%s", path)
	}

	defer preserveIPFSHttpCli()()
	cid := uploadIPFSFile(t, ipfsURL, fn("liveness_credential.json-ld"))
	require.Equal(t, "QmcomGJQwJDCg3RE6FjsFYCjjMSTWJXY3fUWeq43Mc5CCJ", cid)

	in, err := os.ReadFile(fn("auth_response_without_options.json"))
	require.NoError(t, err)

	defer httpmock.MockHTTPClient(t,
		map[string]string{
			`https://localhost:8080%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x7c1a66de0000000000000000000000000000000000000000000000000000000000000000","to":"0x3c9acb2205aa72a05f6d77d708b5cf85fca3a896"},"latest"]}`:                                                                 fn("httpresp_eth_state_auth_input_0x7c1a66de0000000000000000000000000000000000000000000000000000000000000000.json"),
			`https://localhost:8080%%%{"jsonrpc":"2.0","id":2,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x53c87312000ce0114a0c3cdd02a4c5f0b761f51d51da5903ea12680b30e3c2c06b33b101114a0c3cdd02a4c5f0b761f51d51da5903ea12680b30e3c2c06b33d3792201c1","to":"0x3c9acb2205aa72a05f6d77d708b5cf85fca3a896"},"latest"]}`: fn("httpresp_eth_state_genesis_not_exist_0x53c87312000ce0114a0c3cdd02a4c5f0b761f51d51da5903ea12680b30e3c2c06b33b101114a0c3cdd02a4c5f0b761f51d51da5903ea12680b30e3c2c06b33d3792201c1.json"),
		},
		httpmock.IgnoreUntouchedURLs(),
	)()

	cfg := EnvConfig{
		ChainConfigs: map[core.ChainID]ChainConfig{
			45056: {
				RPCUrl:            "https://localhost:8080",
				StateContractAddr: common.HexToAddress("0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896"),
			},
		},
		IPFSNodeURL: ipfsURL,
	}

	_, err = VerifyAuthResponse(context.Background(), cfg, in)
	require.Error(t, err, pubsignals.ErrProofGenerationOutdated)
}

func BenchmarkProofVerification_OnlineContract(b *testing.B) {
	fn := func(path string) string {
		return fmt.Sprintf("testdata/%s", path)
	}

	in, err := os.ReadFile(fn("auth_response_with_options_jwz_format.json"))
	require.NoError(b, err)

	cfg := EnvConfig{
		ChainConfigs: map[core.ChainID]ChainConfig{
			45056: {
				RPCUrl:            "https://rpc-mainnet.billions.network",
				StateContractAddr: common.HexToAddress("0x3C9acB2205Aa72A05F6D77d708b5Cf85FCa3a896"),
			},
		},
		IPFSGatewayURL: "https://ipfs-proxy-cache.privado.id",
	}

	for b.Loop() {
		_, err := VerifyAuthResponse(context.Background(), cfg, in)
		if err != nil {
			b.Fatal(err)
		}
	}
}
