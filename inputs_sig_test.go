package c_polygonid

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path"
	"sync"
	"testing"

	httpmock "github.com/0xPolygonID/c-polygonid/testing"
	"github.com/ethereum/go-ethereum/common"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

func TestHexHash_UnmarshalJSON(t *testing.T) {
	s := `"2b9d4abe9012cc337d3d347b66659cc45091f822dccb004d88d9f1459e2de306"`
	var h hexHash
	err := h.UnmarshalJSON([]byte(s))
	require.NoError(t, err)
}

func uploadIPFSFile(t testing.TB, ipfsURL string, fName string) string {
	cli := &ipfsCli{rpcURL: ipfsURL}

	f, err := os.Open(fName)
	require.NoError(t, err)
	// no need to close f

	// Context is a pure file (no directory)
	cid, err := cli.Add(context.Background(), f, path.Base(fName))
	require.NoError(t, err)

	return cid
}

func readFixtureFile(name string) []byte {
	fileBytes, err := os.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return fileBytes
}

// Set HTTP client for IPFS to new one to prevent IPFS client going through
// mocked HTTP client.
func preserveIPFSHttpCli() func() {
	oldDefaultHTTPClient := defaultIPFSHttpCli
	defaultIPFSHttpCli = &http.Client{Transport: http.DefaultTransport}
	return func() {
		defaultIPFSHttpCli = oldDefaultHTTPClient
	}
}

func TestPrepareInputs(t *testing.T) {

	type PrepareInputsFn func(
		ctx context.Context, cfg EnvConfig, in []byte) (
		AtomicQueryInputsResponse, error)

	doTest := func(t testing.TB, inFile, wantOutFile string,
		fn PrepareInputsFn, wantVR map[string]any, cfg EnvConfig,
		wantErr string) {

		ctx := context.Background()
		out, err := fn(ctx, cfg, readFixtureFile(inFile))
		if wantErr != "" {
			require.EqualError(t, err, wantErr)
			return
		}
		require.NoError(t, err)

		assertEqualWithoutTimestamp(t, wantOutFile, out.Inputs)

		if wantVR == nil {
			require.Nil(t, out.VerifiablePresentation)
		} else {
			require.Equal(t, wantVR, out.VerifiablePresentation)
		}
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

	t.Run("AtomicQueryMtpV2Onchain", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t,
			map[string]string{
				`http://localhost:8545%%%{"jsonrpc":"2.0","method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0xb4bdea55000e5102b2f7a54e61db03f6c656f65062f4b11b9dd52a1702c2bfdc379d1202","to":"0x134b1be34911e39a8397ec6289782989729807a4"},"latest"]}`:                                                                 "testdata/httpresp_eth_state_2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X.json",
				`http://localhost:8545%%%{"jsonrpc":"2.0","method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x110c96a7000e5102b2f7a54e61db03f6c656f65062f4b11b9dd52a1702c2bfdc379d12020000000000000000000000000000000000000000000000000000000026d96d5e","to":"0x49b84b9dd137de488924b18299de8bf46fd11469"},"latest"]}`: `testdata/httpresp_eth_iden3state_2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X_rev_status_651783518.json`,
				"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld":                                         "testdata/httpresp_iden3proofs.jsonld",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": "testdata/httpresp_kyc-v3.json-ld",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld":  "testdata/httpresp_kyc_v4.jsonld",
			},
			httpmock.IgnoreUntouchedURLs(),
			httpmock.WithPostRequestBodyProcessor(removeIdFromEthBody))()
		cfg := EnvConfig{
			ChainConfigs: map[core.ChainID]ChainConfig{
				80001: {
					RPCUrl:            "http://localhost:8545",
					StateContractAddr: common.HexToAddress("0x134B1BE34911E39A8397ec6289782989729807a4"),
				},
			},
		}

		doTest(t, "atomic_query_mtp_v2_on_chain_status_inputs.json",
			"atomic_query_mtp_v2_on_chain_status_output.json",
			AtomicQueryMtpV2InputsFromJson,
			nil, cfg, "")
	})

	t.Run("AtomicQueryMtpV2Onchain - no roots in identity tree store", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			`http://localhost:8545%%%{"jsonrpc":"2.0","method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0xb4bdea55000e5102b2f7a54e61db03f6c656f65062f4b11b9dd52a1702c2bfdc379d1202","to":"0x134b1be34911e39a8397ec6289782989729807a4"},"latest"]}`:                                                                 "testdata/httpresp_eth_state_2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X.json",
			`http://localhost:8545%%%{"jsonrpc":"2.0","method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x110c96a7000e5102b2f7a54e61db03f6c656f65062f4b11b9dd52a1702c2bfdc379d12020000000000000000000000000000000000000000000000000000000026d96d5e","to":"0x49b84b9dd137de488924b18299de8bf46fd11469"},"latest"]}`: `testdata/httpresp_eth_tree_store_2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X_no_roots.json`,
			"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld":                                         "testdata/httpresp_iden3proofs.jsonld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld":  "testdata/httpresp_kyc_v4.jsonld",
		},
			httpmock.IgnoreUntouchedURLs(),
			httpmock.WithPostRequestBodyProcessor(removeIdFromEthBody))()
		cfg := EnvConfig{
			ChainConfigs: map[core.ChainID]ChainConfig{
				80001: {
					RPCUrl:            "http://localhost:8545",
					StateContractAddr: common.HexToAddress("0x134B1BE34911E39A8397ec6289782989729807a4"),
				},
			},
		}

		doTest(t, "atomic_query_mtp_v2_on_chain_status_inputs.json", "",
			AtomicQueryMtpV2InputsFromJson, nil, cfg,
			"GetRevocationProof smart contract call [GetRevocationStatus]: roots were not saved to identity tree store")
	})

	t.Run("AtomicQueryMtpV2InputsFromJson", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9/claims/revocation/status/380518664": "testdata/httpresp_rev_status_380518664.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                 "testdata/httpresp_iden3credential_v2.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                             "testdata/httpresp_kyc-v3.json-ld",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_mtp_v2_inputs.json",
			"atomic_query_mtp_v2_output.json", AtomicQueryMtpV2InputsFromJson,
			nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryMtpV2InputsFromJson NonMerklized", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                 "testdata/httpresp_iden3credential_v2.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3-non-merklized.json-ld":                                               "testdata/httpresp_kyc-v3-non-merklized.json-ld",
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9/claims/revocation/status/118023115": "testdata/httpresp_rev_status_118023115.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_mtp_v2_non_merklized_inputs.json",
			"atomic_query_mtp_v2_non_merklized_output.json",
			AtomicQueryMtpV2InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryMtpV2InputsFromJson NonMerklized Disclosure",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                 "testdata/httpresp_iden3credential_v2.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3-non-merklized.json-ld":                                               "testdata/httpresp_kyc-v3-non-merklized.json-ld",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9/claims/revocation/status/118023115": "testdata/httpresp_rev_status_118023115.json",
			}, httpmock.IgnoreUntouchedURLs())()

			wantVerifiablePresentation := map[string]any{
				"@context": []any{"https://www.w3.org/2018/credentials/v1"},
				"@type":    "VerifiablePresentation",
				"verifiableCredential": map[string]any{
					"@context": []any{
						"https://www.w3.org/2018/credentials/v1",
						"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3-non-merklized.json-ld",
					},
					"@type": []any{"VerifiableCredential", "KYCAgeCredential"},
					"credentialSubject": map[string]any{
						"@type":        "KYCAgeCredential",
						"documentType": float64(99),
					},
				},
			}

			doTest(t,
				"atomic_query_mtp_v2_non_merklized_disclosure_inputs.json",
				"atomic_query_mtp_v2_non_merklized_output.json",
				AtomicQueryMtpV2InputsFromJson, wantVerifiablePresentation,
				EnvConfig{}, "")
		})

	t.Run("AtomicQuerySigV2InputsFromJson Disclosure", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
		}, httpmock.IgnoreUntouchedURLs())()

		wantVerifiablePresentation := map[string]any{
			"@context": []any{"https://www.w3.org/2018/credentials/v1"},
			"@type":    "VerifiablePresentation",
			"verifiableCredential": map[string]any{
				"@context": []any{
					"https://www.w3.org/2018/credentials/v1",
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				},
				"@type": []any{"VerifiableCredential", "KYCAgeCredential"},
				"credentialSubject": map[string]any{
					"@type":        "KYCAgeCredential",
					"documentType": float64(2),
				},
			},
		}

		doTest(t, "atomic_query_sig_v2_merklized_disclosure_inputs.json",
			"atomic_query_sig_v2_merklized_output.json",
			AtomicQuerySigV2InputsFromJson, wantVerifiablePresentation,
			EnvConfig{}, "")
	})

	t.Run("AtomicQuerySigV2InputsFromJson", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_sig_v2_merklized_inputs.json",
			"atomic_query_sig_v2_merklized_output.json",
			AtomicQuerySigV2InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQuerySigV2InputsFromJson - ipfs", func(t *testing.T) {
		ipfsURL := os.Getenv("IPFS_URL")
		if ipfsURL == "" {
			t.Skip("IPFS_URL is not set")
		}

		defer preserveIPFSHttpCli()()

		cid := uploadIPFSFile(t, ipfsURL, "testdata/httpresp_kyc-v3.json-ld")
		// CID should correspond to the URL from the
		// atomic_query_sig_v2_merklized_ipfs_inputs.json test input.
		require.Equal(t, "QmXwNybNDvsdva11ypERby1nYnR5vJPTy9ZvHdnhaPMD7z", cid)

		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_sig_v2_merklized_ipfs_inputs.json",
			"atomic_query_sig_v2_merklized_output.json",
			AtomicQuerySigV2InputsFromJson, nil,
			EnvConfig{IPFSNodeURL: ipfsURL}, "")
	})

	t.Run("AtomicQuerySigV2InputsFromJson - noop", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_sig_v2_merklized_noop_inputs.json",
			"atomic_query_sig_v2_merklized_noop_output.json",
			AtomicQuerySigV2InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQuerySigV2InputsFromJson - revoked", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/105": "testdata/httpresp_rev_status_105.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_sig_v2_merklized_revoked_inputs.json", "",
			AtomicQuerySigV2InputsFromJson, nil, EnvConfig{},
			"credential is revoked")
	})

	t.Run("AtomicQuerySigV2InputsFromJson - skip revocation check",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                  "testdata/httpresp_kyc-v3.json-ld",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                      "testdata/httpresp_iden3credential_v2.json",
				"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":   "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
				"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/105": "testdata/httpresp_rev_status_105.json",
			}, httpmock.IgnoreUntouchedURLs())()

			doTest(t,
				"atomic_query_sig_v2_merklized_skip_revocation_check_inputs.json",
				"atomic_query_sig_v2_merklized_skip_revocation_check_output.json",
				AtomicQuerySigV2InputsFromJson, nil, EnvConfig{},
				"")
		})

	t.Run("AtomicQuerySigV2InputsFromJson NonMerklized", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                  "testdata/httpresp_iden3credential_v2.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3-non-merklized.json-ld":                                                "testdata/httpresp_kyc-v3-non-merklized.json-ld",
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_sig_v2_non_merklized_inputs.json",
			"atomic_query_sig_v2_non_merklized_output.json",
			AtomicQuerySigV2InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQuerySigV2InputsFromJson NonMerklized - noop",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
			}, httpmock.IgnoreUntouchedURLs())()

			doTest(t, "atomic_query_sig_v2_non_merklized_noop_inputs.json",
				"atomic_query_sig_v2_non_merklized_noop_output.json",
				AtomicQuerySigV2InputsFromJson, nil, EnvConfig{}, "")
		})

	t.Run("AtomicQuerySigV2InputsFromJson NonMerklized Disclosure",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                  "testdata/httpresp_iden3credential_v2.json",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3-non-merklized.json-ld":                                                "testdata/httpresp_kyc-v3-non-merklized.json-ld",
			}, httpmock.IgnoreUntouchedURLs())()

			wantVerifiablePresentation := map[string]any{
				"@context": []any{"https://www.w3.org/2018/credentials/v1"},
				"@type":    "VerifiablePresentation",
				"verifiableCredential": map[string]any{
					"@context": []any{
						"https://www.w3.org/2018/credentials/v1",
						"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3-non-merklized.json-ld",
					},
					"@type": []any{"VerifiableCredential", "KYCAgeCredential"},
					"credentialSubject": map[string]any{
						"@type":        "KYCAgeCredential",
						"documentType": float64(99),
					},
				},
			}

			doTest(t,
				"atomic_query_sig_v2_non_merklized_disclosure_inputs.json",
				"atomic_query_sig_v2_non_merklized_output.json",
				AtomicQuerySigV2InputsFromJson, wantVerifiablePresentation,
				EnvConfig{}, "")
		})

	t.Run("AtomicQuerySigV2OnChainInputsFromJson",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/3972757": "testdata/httpresp_rev_status_3972757.json",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/0":       "testdata/httpresp_rev_status_qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV_0.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                               "testdata/httpresp_iden3credential_v2.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                           "testdata/httpresp_kyc-v3.json-ld",
			}, httpmock.IgnoreUntouchedURLs())()

			doTest(t,
				"atomic_query_sig_v2_on_chain_input.json",
				"atomic_query_sig_v2_on_chain_output.json",
				AtomicQuerySigV2OnChainInputsFromJson, nil, EnvConfig{}, "")
		})

	t.Run("AtomicQueryMtpV2OnChainInputsFromJson",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/3972757": "testdata/httpresp_rev_status_3972757.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                               "testdata/httpresp_iden3credential_v2.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                           "testdata/httpresp_kyc-v3.json-ld",
			}, httpmock.IgnoreUntouchedURLs())()

			doTest(t,
				"atomic_query_mtp_v2_on_chain_input.json",
				"atomic_query_mtp_v2_on_chain_output.json",
				AtomicQueryMtpV2OnChainInputsFromJson, nil, EnvConfig{}, "")
		})

	t.Run("AtomicQuerySigV2InputsFromJson - RHS - empty revocation tree",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				`http://localhost:8545%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0xb4bdea55000d5228592025eac998034e2c03f242819d84806687a3b0c95eefa295ca1202","to":"0x6f0a444df4d231d85f66e4836f836034f0fefe24"},"latest"]}`: "testdata/httpresp_eth_resp1.json",
				"http://localhost:8003/node/8ef2ce21e01d86ec2376fe28bf6b47a84d08f8628d970474a2698cebf94bca1c":                "testdata/httpresp_rhs_8ef2ce21e01d86ec2376fe28bf6b47a84d08f8628d970474a2698cebf94bca1c.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
			}, httpmock.IgnoreUntouchedURLs())()

			cfg := EnvConfig{
				EthereumURL: "http://localhost:8545",
				StateContractAddr: common.HexToAddress(
					"0x6F0a444Df4d231D85F66e4836f836034F0feFE24"),
			}
			doTest(t, "atomic_query_sig_v2_merklized_rhs_inputs.json",
				"atomic_query_sig_v2_merklized_rhs_output.json",
				AtomicQuerySigV2InputsFromJson, nil, cfg, "")
		})

	t.Run("AtomicQuerySigV2InputsFromJson - RHS - non-empty revocation tree",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				`http://localhost:8545%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0xb4bdea55000d5228592025eac998034e2c03f242819d84806687a3b0c95eefa295ca1202","to":"0x6f0a444df4d231d85f66e4836f836034f0fefe24"},"latest"]}`: "testdata/httpresp_eth_resp2.json",
				"http://localhost:8003/node/5ce9b64f8472b094191230e881ed8d85ce215de414b496eb029161c30d654b20":                "testdata/httpresp_rhs_5ce9b64f8472b094191230e881ed8d85ce215de414b496eb029161c30d654b20.json",
				"http://localhost:8003/node/d55bad23c75687c86105589f50612a97ac1904cb0bbc13927a3d6a68321f9f29":                "testdata/httpresp_rhs_d55bad23c75687c86105589f50612a97ac1904cb0bbc13927a3d6a68321f9f29.json",
				"http://localhost:8003/node/95fff1dd8f67374e1eebf9b462a6189517d438883be332bb9f1eb4f41c066014":                "testdata/httpresp_rhs_95fff1dd8f67374e1eebf9b462a6189517d438883be332bb9f1eb4f41c066014.json",
				"http://localhost:8003/node/243781162f6392357e51ea0cc6b1086edcb725e27e747be0839fff8beafd4e2a":                "testdata/httpresp_rhs_243781162f6392357e51ea0cc6b1086edcb725e27e747be0839fff8beafd4e2a.json",
				"http://localhost:8003/node/012cf3eb22da52668f730fee0671b6c1cec67af7ab43c77e3a9d2d4d4a34e323":                "testdata/httpresp_rhs_012cf3eb22da52668f730fee0671b6c1cec67af7ab43c77e3a9d2d4d4a34e323.json",
				"http://localhost:8003/node/7e1415c74c9dacbd81786ab93f3bf50425f10566f96d1bf1a47d7d6218020c2d":                "testdata/httpresp_rhs_7e1415c74c9dacbd81786ab93f3bf50425f10566f96d1bf1a47d7d6218020c2d.json",
				"http://localhost:8003/node/d543edb99a153f54e1338f3c9515bc49ccc4c468433de880c7299b1b0fc16017":                "testdata/httpresp_rhs_d543edb99a153f54e1338f3c9515bc49ccc4c468433de880c7299b1b0fc16017.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
			}, httpmock.IgnoreUntouchedURLs())()

			cfg := EnvConfig{
				EthereumURL: "http://localhost:8545",
				StateContractAddr: common.HexToAddress(
					"0x6F0a444Df4d231D85F66e4836f836034F0feFE24"),
			}
			doTest(t, "atomic_query_sig_v2_merklized_rhs_inputs.json",
				"atomic_query_sig_v2_merklized_rhs_nonempty_output.json",
				AtomicQuerySigV2InputsFromJson, nil, cfg, "")
		})

	t.Run("AtomicQuerySigV2InputsFromJson - RHS - revoked",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				`http://localhost:8545%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0xb4bdea55000d5228592025eac998034e2c03f242819d84806687a3b0c95eefa295ca1202","to":"0x6f0a444df4d231d85f66e4836f836034f0fefe24"},"latest"]}`: "testdata/httpresp_eth_resp2.json",
				"http://localhost:8003/node/5ce9b64f8472b094191230e881ed8d85ce215de414b496eb029161c30d654b20": "testdata/httpresp_rhs_5ce9b64f8472b094191230e881ed8d85ce215de414b496eb029161c30d654b20.json",
				"http://localhost:8003/node/d55bad23c75687c86105589f50612a97ac1904cb0bbc13927a3d6a68321f9f29": "testdata/httpresp_rhs_d55bad23c75687c86105589f50612a97ac1904cb0bbc13927a3d6a68321f9f29.json",
				"http://localhost:8003/node/a75cc7f84f279f758427e8f1ec26d2d7dcac0fd545098ef668dde0d2f90ca809": "testdata/httpresp_rhs_a75cc7f84f279f758427e8f1ec26d2d7dcac0fd545098ef668dde0d2f90ca809.json",
				"http://localhost:8003/node/ce051a956948154312d91a406b52120fd689376c1b675699053cc1d7cafa4f04": "testdata/httpresp_rhs_ce051a956948154312d91a406b52120fd689376c1b675699053cc1d7cafa4f04.json",
				"http://localhost:8003/node/3ecaca31559a389adb870fa1347b8487dee24406a7c9959334d3f36b65c3ba1d": "testdata/httpresp_rhs_3ecaca31559a389adb870fa1347b8487dee24406a7c9959334d3f36b65c3ba1d.json",
			}, httpmock.IgnoreUntouchedURLs())()

			cfg := EnvConfig{
				EthereumURL: "http://localhost:8545",
				StateContractAddr: common.HexToAddress(
					"0x6F0a444Df4d231D85F66e4836f836034F0feFE24"),
			}
			doTest(t, "atomic_query_sig_v2_merklized_rhs_revoked_inputs.json",
				"", AtomicQuerySigV2InputsFromJson, nil, cfg,
				"credential is revoked")
		})

	t.Run("AtomicQuerySigV2InputsFromJson Nested Disclosure", func(t *testing.T) {

		ipfsURL := os.Getenv("IPFS_URL")
		if ipfsURL == "" {
			t.Skip("IPFS_URL is not set")
		}

		defer preserveIPFSHttpCli()()

		cid := uploadIPFSFile(t, ipfsURL, "testdata/ipfs_QmcAJCriUKiU4WQogfhqpi6j8S8XTmZdmg7hpaVr4eGynW.json-ld")
		// CID should correspond to the URL
		require.Equal(t, "QmcAJCriUKiU4WQogfhqpi6j8S8XTmZdmg7hpaVr4eGynW", cid)

		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://dev.polygonid.me/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLPqvayNQz9TA2r5VPxUugoF18teGU583zJ859wfy/claims/revocation/status/214490175":  "testdata/httpresp_rev_status_214490175.json",
			"https://dev.polygonid.me/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qLPqvayNQz9TA2r5VPxUugoF18teGU583zJ859wfy/claims/revocation/status/2575161389": "testdata/httpresp_rev_status_2575161389.json",
			"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld": "testdata/httpresp_iden3proofs.jsonld",
		}, httpmock.IgnoreUntouchedURLs())()

		wantVerifiablePresentation := map[string]any{
			"@context": []any{"https://www.w3.org/2018/credentials/v1"},
			"@type":    "VerifiablePresentation",
			"verifiableCredential": map[string]any{
				"@context": []any{
					"https://www.w3.org/2018/credentials/v1",
					"ipfs://QmcAJCriUKiU4WQogfhqpi6j8S8XTmZdmg7hpaVr4eGynW",
				},
				"@type": []any{"VerifiableCredential", "DeliveryAddress"},
				"credentialSubject": map[string]any{
					"@type": "DeliveryAddress",
					"postalProviderInformation": map[string]any{
						"address1": map[string]any{
							"name": "addressName",
						},
					},
				},
			},
		}

		doTest(t, "atomic_query_sig_v2_nested_selective_disclosure_inputs.json",
			"atomic_query_sig_v2_nested_selective_disclosure_output.json",
			AtomicQuerySigV2InputsFromJson, wantVerifiablePresentation,
			EnvConfig{IPFSNodeURL: ipfsURL}, "")
	})

	t.Run("AtomicQueryV3InputsFromJson - MTP", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
			//"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_v3_mtp_inputs.json",
			"atomic_query_v3_mtp_output.json",
			AtomicQueryV3InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryV3InputsFromJson - Sig", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_v3_sig_inputs.json",
			"atomic_query_v3_sig_output.json",
			AtomicQueryV3InputsFromJson, nil, EnvConfig{}, "")
	})

	// Inputs does not include proof type, but the query has both. Choose MTP.
	t.Run("AtomicQueryV3InputsFromJson - No proof type, Have both", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_v3_no_proof_type_both_have_inputs.json",
			"atomic_query_v3_mtp_output.json",
			AtomicQueryV3InputsFromJson, nil, EnvConfig{}, "")
	})

	// Inputs does not include proof type, but the query contains Sig one.
	t.Run("AtomicQueryV3InputsFromJson - No proof type, Sig only", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_v3_no_proof_type_sig_only_inputs.json",
			"atomic_query_v3_sig_output.json",
			AtomicQueryV3InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryV3OnChainInputsFromJson - MTP", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/3972757": "testdata/httpresp_rev_status_3972757.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                           "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                               "testdata/httpresp_iden3credential_v2.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_v3_on_chain_mtp_inputs.json",
			"atomic_query_v3_on_chain_mtp_output.json",
			AtomicQueryV3OnChainInputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryV3OnChainInputsFromJson - Sig", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/0":       "testdata/httpresp_rev_status_qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV_0.json",
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/3972757": "testdata/httpresp_rev_status_3972757.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                           "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                               "testdata/httpresp_iden3credential_v2.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_v3_on_chain_sig_inputs.json",
			"atomic_query_v3_on_chain_sig_output.json",
			AtomicQueryV3OnChainInputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryV3InputsFromJson - Sig - Selective Disclosure", func(t *testing.T) {

		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
		}, httpmock.IgnoreUntouchedURLs())()

		wantVerifiablePresentation := map[string]any{
			"@context": []any{"https://www.w3.org/2018/credentials/v1"},
			"@type":    "VerifiablePresentation",
			"verifiableCredential": map[string]any{
				"@context": []any{
					"https://www.w3.org/2018/credentials/v1",
					"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
				},
				"@type": []any{"VerifiableCredential", "KYCAgeCredential"},
				"credentialSubject": map[string]any{
					"@type":        "KYCAgeCredential",
					"documentType": float64(2),
				},
			},
		}

		doTest(t, "atomic_query_v3_sig_selective_disclosure_inputs.json",
			"atomic_query_v3_sig_selective_disclosure_output.json",
			AtomicQueryV3InputsFromJson, wantVerifiablePresentation,
			EnvConfig{}, "")
	})

	t.Run("AtomicQueryV3OnChainInputsFromJson - Transaction Data", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/3972757": "testdata/httpresp_rev_status_3972757.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                           "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                               "testdata/httpresp_iden3credential_v2.json",
		}, httpmock.IgnoreUntouchedURLs())()

		doTest(t, "atomic_query_v3_on_chain_tx_data_inputs.json",
			"atomic_query_v3_on_chain_tx_data_output.json",
			AtomicQueryV3OnChainInputsFromJson, nil, EnvConfig{}, "")
	})

}

func TestEnvConfig_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		title string
		in    string
		want  EnvConfig
	}{
		{
			title: "one",
			in: `{
  "ethereumUrl": "http://localhost:8545",
  "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655",
  "reverseHashServiceUrl": "http://localhost:8003"
}`,
			want: EnvConfig{
				EthereumURL:           "http://localhost:8545",
				StateContractAddr:     common.HexToAddress("0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"),
				ReverseHashServiceUrl: "http://localhost:8003",
			},
		},
		{
			title: "ipfs node",
			in: `{
  "ethereumUrl": "http://localhost:8545",
  "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655",
  "reverseHashServiceUrl": "http://localhost:8003",
  "ipfsNodeUrl": "http://localhost:5001"
}`,
			want: EnvConfig{
				EthereumURL:           "http://localhost:8545",
				StateContractAddr:     common.HexToAddress("0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"),
				ReverseHashServiceUrl: "http://localhost:8003",
				IPFSNodeURL:           "http://localhost:5001",
			},
		},
		{
			title: "per chain configs",
			in: `{
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
      "rpcUrl": "http://localhost:8545",
      "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"
    },
    "0X11": {
      "rpcUrl": "http://localhost:8545",
      "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"
    }
  }
}`,
			want: EnvConfig{
				EthereumURL:           "http://localhost:8545",
				StateContractAddr:     common.HexToAddress("0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"),
				ReverseHashServiceUrl: "http://localhost:8003",
				IPFSNodeURL:           "http://localhost:5001",
				ChainConfigs: map[core.ChainID]ChainConfig{
					1: {
						RPCUrl:            "http://localhost:8545",
						StateContractAddr: common.HexToAddress("0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"),
					},
					16: {
						RPCUrl:            "http://localhost:8545",
						StateContractAddr: common.HexToAddress("0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"),
					},
					17: {
						RPCUrl:            "http://localhost:8545",
						StateContractAddr: common.HexToAddress("0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"),
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.title, func(t *testing.T) {
			var got EnvConfig
			err := json.Unmarshal([]byte(tc.in), &got)
			require.NoError(t, err)
			require.Equal(t, tc.want, got)
		})
	}
}

func hexFromIntStr(intStr string) *merkletree.Hash {
	i, ok := new(big.Int).SetString(intStr, 10)
	if !ok {
		panic(intStr)
	}
	h, err := merkletree.NewHashFromBigInt(i)
	if err != nil {
		panic(err)
	}
	return h
}

func must[T any](fn func() (T, error)) T {
	v, err := fn()
	if err != nil {
		panic(err)
	}
	return v
}

func assertEqualWithoutTimestamp(t testing.TB, wantFName string,
	im circuits.InputsMarshaller) {

	jsonWant, err := os.ReadFile("testdata/" + wantFName)
	require.NoError(t, err)

	var wantObj jsonObj
	err = json.Unmarshal(jsonWant, &wantObj)
	require.NoError(t, err)

	inputsBytes, err := im.InputsMarshal()
	require.NoError(t, err)

	var inputsObj jsonObj
	err = json.Unmarshal(inputsBytes, &inputsObj)
	require.NoError(t, err)

	wantObj["timestamp"] = inputsObj["timestamp"]

	require.Equal(t, wantObj, inputsObj, "file name: %s\nwant: %s\ngot: %s",
		wantFName, jsonWant, inputsBytes)
}

func TestAtomicQuerySigV2OnChainInputsFromJson(t *testing.T) {
	inBytes, err := os.ReadFile(
		"testdata/atomic_query_sig_v2_on_chain_input.json")
	require.NoError(t, err)

	var obj onChainInputsRequest
	err = json.Unmarshal(inBytes, &obj)
	require.NoError(t, err)

	wantTreeState := circuits.TreeState{
		State: hexFromIntStr(
			"3455793648389793511224972913807237799755511487265044435383221641855224272477"),
		ClaimsRoot: hexFromIntStr(
			"12863526460000963806360638100765589244767101189459134829137262186265339590400"),
		RevocationRoot: hexFromIntStr("0"),
		RootOfRoots:    hexFromIntStr("0"),
	}
	require.Equal(t, &wantTreeState, obj.TreeState)

	wantGistProof := circuits.GISTProof{
		Root: hexFromIntStr("5005919421435686441886912154983595081356506147906956636160716123399604497694"),
		Proof: must(func() (*merkletree.Proof, error) {
			return merkletree.NewProofFromData(false,
				[]*merkletree.Hash{
					hexFromIntStr("9572034982910400342435969278331518000622332242067560582395787734704675688171"),
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero, &merkletree.HashZero,
					&merkletree.HashZero,
				},
				nil)
		}),
	}
	require.Equal(t, &wantGistProof, obj.GistProof)
}

func Test_resolverOnChainRevocationStatus(t *testing.T) {
	t.Skip("skipping test, this is for debugging OnchainRevocation status only")
	cfg := EnvConfig{
		EthereumURL:       "<RPC>",
		StateContractAddr: common.HexToAddress("0x66277D6E1Ad434772AF2A88de2901e3435Dbb8E6"),
	}

	did, err := w3c.ParseDID("did:polygonid:polygon:mumbai:2qCU58EJgrEM9Lvkv6vTqkybetLHDL4yfpRNS32eas")
	require.NoError(t, err)
	id, err := core.IDFromDID(*did)
	require.NoError(t, err)
	status := &verifiable.CredentialStatus{
		ID:              "did:polygonid:polygon:mumbai:2qCU58EJgrEM9Lvkv6vTqkybetLHDL4yfpRNS32eas/credentialStatus?revocationNonce=689689820&contractAddress=80001:0xA5055e131A3544BfB4eA20CD269e6f738fAE32B0",
		Type:            "Iden3OnchainSparseMerkleTreeProof2023",
		RevocationNonce: 689689820,
	}

	got, err := resolverOnChainRevocationStatus(context.Background(), cfg, &id, status)
	require.NoError(t, err)

	proofJson, _ := json.Marshal(got)
	fmt.Println(string(proofJson))

	fmt.Printf("%+v\n", got.TreeState)
	fmt.Println("RevTreeRoot : ", got.TreeState.RevocationRoot.BigInt())

	root, _ := merkletree.RootFromProof(got.Proof, big.NewInt(689689820), big.NewInt(0))
	fmt.Println("Root : ", root.BigInt())

	// ????
	nonce, b := new(big.Int).SetString("689689820", 10)
	require.True(t, b)

	fmt.Printf("Proof %+v\n", got.Proof)

	proofValid := merkletree.VerifyProof(got.TreeState.RevocationRoot,
		got.Proof, nonce, big.NewInt(0))

	require.True(t, proofValid)

	state, _ := poseidon.Hash([]*big.Int{got.TreeState.ClaimsRoot.BigInt(), got.TreeState.RevocationRoot.BigInt(),
		got.TreeState.RootOfRoots.BigInt()})

	fmt.Println("State : ", state)
	require.Equal(t, state, got.TreeState.State.BigInt())
}

func TestNetworkCfgByID(t *testing.T) {
	defaultChainCfg := ChainConfig{
		RPCUrl:            "http://host2.com/default",
		StateContractAddr: common.BytesToAddress([]byte{1}),
	}

	cfg := EnvConfig{
		ChainConfigs: PerChainConfig{
			80001: ChainConfig{
				RPCUrl:            "http://host1.com/mumbai",
				StateContractAddr: common.BytesToAddress([]byte{2}),
			},
		},
		EthereumURL:           defaultChainCfg.RPCUrl,
		StateContractAddr:     defaultChainCfg.StateContractAddr,
		ReverseHashServiceUrl: "",
		IPFSNodeURL:           "",
	}

	emptyCfg := EnvConfig{}

	mkID := func(t testing.TB, method core.DIDMethod,
		blockchain core.Blockchain, network core.NetworkID) *core.ID {

		tp, err := core.BuildDIDType(method, blockchain, network)
		require.NoError(t, err)
		id, err := core.NewIDFromIdenState(tp, big.NewInt(1))
		require.NoError(t, err)
		return id
	}

	t.Run("chain config found", func(t *testing.T) {
		polygonMumbaiID := mkID(t, core.DIDMethodPolygonID, core.Polygon,
			core.Mumbai)
		chainCfg, err := cfg.networkCfgByID(polygonMumbaiID)
		require.NoError(t, err)
		require.Equal(t, cfg.ChainConfigs[80001], chainCfg)
	})

	t.Run("default chain config", func(t *testing.T) {
		ethMainID := mkID(t, core.DIDMethodIden3, core.Ethereum, core.Main)
		chainCfg, err := cfg.networkCfgByID(ethMainID)
		require.NoError(t, err)
		require.Equal(t, defaultChainCfg, chainCfg)
	})

	t.Run("config is empty", func(t *testing.T) {
		ethMainID := mkID(t, core.DIDMethodIden3, core.Ethereum, core.Main)
		_, err := emptyCfg.networkCfgByID(ethMainID)
		require.EqualError(t, err, "ethereum url is empty")
	})

}

func TestRHSBaseURL(t *testing.T) {
	mkHash := func(t testing.TB, hexStr string) *merkletree.Hash {
		h, err := merkletree.NewHashFromHex(hexStr)
		require.NoError(t, err)
		return h
	}

	testCases := []struct {
		title   string
		in      string
		baseURL string
		hash    *merkletree.Hash
		wantErr string
	}{
		{
			title:   "old format 1",
			in:      "http://localhost:8003/node/",
			baseURL: "http://localhost:8003/",
			hash:    nil,
			wantErr: "",
		},
		{
			title:   "old format 2",
			in:      "http://localhost:8003/node/",
			baseURL: "http://localhost:8003/",
			hash:    nil,
			wantErr: "",
		},
		{
			title:   "without node suffix",
			in:      "http://localhost:8003/",
			baseURL: "http://localhost:8003/",
			hash:    nil,
			wantErr: "",
		},
		{
			title:   "with state",
			in:      "http://localhost:8003/node/?state=46a119b1184b2f4256c13633d1f36dc2f489523e14ca4058e1c53324f16a4506",
			baseURL: "http://localhost:8003/",
			hash:    mkHash(t, "46a119b1184b2f4256c13633d1f36dc2f489523e14ca4058e1c53324f16a4506"),
			wantErr: "",
		},
		{
			title:   "error parsing state",
			in:      "http://localhost:8003/node?state=46a119b1184b2f4256c13633d1f36dc2f489523e14ca4058e1c53324f16a45",
			baseURL: "",
			hash:    nil,
			wantErr: "invalid hash length",
		},
	}
	for i := range testCases {
		tc := testCases[i]
		t.Run(tc.title, func(t *testing.T) {
			baseURL, hash, err := rhsBaseURL(tc.in)
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
			} else {
				require.NoError(t, err)
				require.Equal(t, tc.baseURL, baseURL)
				require.Equal(t, tc.hash, hash)
			}
		})
	}
}

func stringFromJsonObj(obj map[string]any, key string) string {
	v, ok := obj[key].(string)
	if ok {
		return v
	}
	return ""
}

func flushCacheDB() {
	db, cleanup, err := getCacheDB()
	if err != nil {
		panic(err)
	}
	defer cleanup()
	err = db.DropAll()
	if err != nil {
		panic(err)
	}
}

type countingDocumentLoader struct {
	documentLoader ld.DocumentLoader
	m              sync.Mutex
	cnt            int
}

func (c *countingDocumentLoader) LoadDocument(u string) (*ld.RemoteDocument, error) {
	c.m.Lock()
	c.cnt++
	c.m.Unlock()
	return c.documentLoader.LoadDocument(u)
}
func (c *countingDocumentLoader) counter() int {
	var cnt int
	c.m.Lock()
	cnt = c.cnt
	c.m.Unlock()
	return cnt
}

func (c *countingDocumentLoader) reset() {
	c.m.Lock()
	c.cnt = 0
	c.m.Unlock()
}

func TestMerklizeCred(t *testing.T) {
	flushCacheDB()

	defer httpmock.MockHTTPClient(t, map[string]string{
		"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld":                                         "testdata/httpresp_iden3proofs.jsonld",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": "testdata/httpresp_kyc-v3.json-ld",
	}, httpmock.IgnoreUntouchedURLs())()

	w3cCred := makeW3CCred(w3cCredDoc)
	wantRoot := "12570949121759664123302463886702240329232804599356712520248381722472565314745"

	documentLoader := &countingDocumentLoader{
		documentLoader: EnvConfig{}.documentLoader(),
	}
	ctx := context.Background()

	mz, err := merklizeCred(ctx, w3cCred, documentLoader, true)
	require.NoError(t, err)
	require.Equal(t, wantRoot, mz.Root().BigInt().String())

	// 3 calls per URL scheme: first for concurrent pre-download schema to put
	// it in cache, second for normalization, and last for compaction
	require.Equal(t, 9, documentLoader.counter())

	// test that following call to merklizeCred does not make any HTTP calls
	documentLoader.reset()

	mz, err = merklizeCred(ctx, w3cCred, documentLoader, true)
	require.NoError(t, err)
	require.Equal(t, wantRoot, mz.Root().BigInt().String())
	require.Equal(t, 0, documentLoader.counter())

	flushCacheDB()
}

func vcCredChecksum(in []byte) []byte {
	var obj struct {
		VerifiableCredentials json.RawMessage `json:"verifiableCredentials"`
	}
	err := json.Unmarshal(in, &obj)
	if err != nil {
		panic(err)
	}

	var w3cCred verifiable.W3CCredential
	err = json.Unmarshal(obj.VerifiableCredentials, &w3cCred)
	if err != nil {
		panic(err)
	}

	w3cCred.Proof = nil
	credentialBytes, err := json.Marshal(w3cCred)
	if err != nil {
		panic(err)
	}

	cacheKey := sha256.Sum256(credentialBytes)
	return cacheKey[:]
}

func TestPreCacheVC(t *testing.T) {
	flushCacheDB()

	defer httpmock.MockHTTPClient(t, map[string]string{
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
	}, httpmock.IgnoreUntouchedURLs())()

	in := readFixtureFile("atomic_query_mtp_v2_inputs.json")
	cfg := EnvConfig{}
	err := PreCacheVC(context.Background(), cfg, in)
	require.NoError(t, err)

	db, closeCache, err := getCacheDB()
	require.NoError(t, err)
	t.Cleanup(closeCache)

	cacheKey := vcCredChecksum(in)
	mz, _, err :=
		getMzCache(context.Background(), db, cacheKey, cfg.documentLoader())
	require.NoError(t, err)
	require.Equal(t,
		"3785566424189219886048259268949130722637888661451289758794190101230031697297",
		mz.Root().BigInt().String())

	err = db.DropAll()
	require.NoError(t, err)
}

func TestVerifierIDFromTxData(t *testing.T) {
	in := txData{
		ContractAddress: common.HexToAddress("0x199194Cb1884BF288757fac94B3349Cefef93629"),
		ChainID:         80001,
	}
	id, err := verifierIDFromTxData(in)
	require.NoError(t, err)
	require.Equal(t, "wuL2hHjCC1L7GL9KpQZtBcFvsyqknxq6otmdWtmqs", id.String())
	require.Equal(t,
		"17966356888215056651324659145404695842840677593163532338422715818832826881",
		id.BigInt().Text(10))
}

func TestNewGenesysID(t *testing.T) {
	in := `{
  "claimsTreeRoot":"16306276920027997118951972513784102597349518910734830865369546877495436692483",
  "blockchain":"polygon",
  "network":"mumbai"
}`

	ctx := context.Background()

	resp, err := NewGenesysID(ctx, EnvConfig{}, []byte(in))
	require.NoError(t, err)
	wantResp := GenesysIDResponse{
		DID:     "did:polygonid:polygon:mumbai:2qMJFBiKaPx3XCKbu1Q45QNaUfdpzk9KkcmNaiyAxc",
		ID:      "2qMJFBiKaPx3XCKbu1Q45QNaUfdpzk9KkcmNaiyAxc",
		IDAsInt: "24121873806719949961527676655485054357633990236472608901764984551147442690",
	}
	require.Equal(t, wantResp, resp)
}

func TestNewGenesysID_DIDMethod(t *testing.T) {
	cfgJSON := `{
  "chainConfigs": {
    "59140": {
      "rpcUrl": "http://localhost:8545",
      "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"
    }
  },
  "didMethods": [
    {
      "name": "polygonid",
      "blockchain": "linea",
      "network": "testnet",
      "networkFlag": "0b01000011",
      "methodByte": "0b00000010",
      "chainID": "59140"
    }
  ]
}`
	cfg, err := NewEnvConfigFromJSON([]byte(cfgJSON))
	require.NoError(t, err)

	in := `{
  "claimsTreeRoot":"16306276920027997118951972513784102597349518910734830865369546877495436692483",
  "blockchain":"linea",
  "network":"testnet"
}`

	ctx := context.Background()

	resp, err := NewGenesysID(ctx, cfg, []byte(in))
	require.NoError(t, err)
	wantResp := GenesysIDResponse{
		DID:     "did:polygonid:linea:testnet:31Akw5AB2xBrwqmbDUA2XoSGCfTepz52q9jmFE4mXA",
		ID:      "31Akw5AB2xBrwqmbDUA2XoSGCfTepz52q9jmFE4mXA",
		IDAsInt: "24460059377712687587111979692736628604804094576108957842967948238113620738",
	}
	require.Equal(t, wantResp, resp)
}

func TestNewGenesysID_DIDMethod_Error(t *testing.T) {
	cfgJSON := `{
  "chainConfigs": {
    "59140": {
      "rpcUrl": "http://localhost:8545",
      "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655"
    }
  }
}`
	cfg, err := NewEnvConfigFromJSON([]byte(cfgJSON))
	require.NoError(t, err)

	in := `{
  "claimsTreeRoot":"16306276920027997118951972513784102597349518910734830865369546877495436692483",
  "blockchain":"linea2",
  "network":"testnet2"
}`

	ctx := context.Background()

	_, err = NewGenesysID(ctx, cfg, []byte(in))
	require.EqualError(t, err, "failed to build DID type: not supported network")
}
