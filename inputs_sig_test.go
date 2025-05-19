package c_polygonid

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"math/big"
	"net/http"
	"os"
	"path"
	"strconv"
	"sync"
	"testing"

	httpmock "github.com/0xPolygonID/c-polygonid/testing"
	"github.com/ethereum/go-ethereum/common"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
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

func removeIdFromEthBody(body []byte) []byte {
	var ethBody map[string]any
	err := json.Unmarshal(body, &ethBody)
	if err != nil {
		panic(err)
	}
	if stringFromJsonObj(ethBody, "jsonrpc") == "2.0" &&
		stringFromJsonObj(ethBody, "method") == "eth_call" {

		delete(ethBody, "id")
	}
	body, err = json.Marshal(ethBody)
	if err != nil {
		panic(err)
	}
	return body
}

func TestPrepareInputs(t *testing.T) {
	mockBadgerLog(t)

	type PrepareInputsFn func(
		ctx context.Context, cfg EnvConfig, in []byte) (
		AtomicQueryInputsResponse, error)

	doTest := func(t testing.TB, inFile, wantOutFile string,
		fn PrepareInputsFn, wantVR map[string]any, cfg EnvConfig,
		wantErr string) {

		err := CleanCache("")
		require.NoError(t, err)

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

	t.Run("GenericInputsFromJson — AtomicQueryMtpV2Onchain", func(t *testing.T) {
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
			GenericInputsFromJson,
			nil, cfg, "")
	})

	t.Run("GenericInputsFromJson — AnonAadhaarV1", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{})()
		cfg := EnvConfig{}

		doTest(t, "anon_aadhaar_v1_inputs.json",
			"anon_aadhaar_v1_output.json",
			GenericInputsFromJson,
			nil, cfg, "")
	})

	t.Run("GenericInputsFromJson — PassportV1", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{})()
		cfg := EnvConfig{}

		doTest(t, "passport_v1_inputs.json",
			"passport_v1_output.json",
			GenericInputsFromJson,
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
			"credential status error: credential status resolve error: GetRevocationProof smart contract call [GetRevocationStatus]: roots were not saved to identity tree store")
	})

	t.Run("AtomicQueryMtpV2InputsFromJson", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9/claims/revocation/status/380518664": "testdata/httpresp_rev_status_380518664.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                 "testdata/httpresp_iden3credential_v2.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                             "testdata/httpresp_kyc-v3.json-ld",
		})()

		doTest(t, "atomic_query_mtp_v2_inputs.json",
			"atomic_query_mtp_v2_output.json", AtomicQueryMtpV2InputsFromJson,
			nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryMtpV2InputsFromJson NonMerklized", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                 "testdata/httpresp_iden3credential_v2.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3-non-merklized.json-ld":                                               "testdata/httpresp_kyc-v3-non-merklized.json-ld",
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9/claims/revocation/status/118023115": "testdata/httpresp_rev_status_118023115.json",
		})()

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
			})()

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
		})()

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
		})()

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
		})()

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
		})()

		doTest(t, "atomic_query_sig_v2_merklized_noop_inputs.json",
			"atomic_query_sig_v2_merklized_noop_output.json",
			AtomicQuerySigV2InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQuerySigV2InputsFromJson - revoked", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/105": "testdata/httpresp_rev_status_105.json",
		})()

		doTest(t, "atomic_query_sig_v2_merklized_revoked_inputs.json", "",
			AtomicQuerySigV2InputsFromJson, nil, EnvConfig{},
			"credential status error: credential is revoked")
	})

	t.Run("AtomicQuerySigV2InputsFromJson - skip revocation check",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                  "testdata/httpresp_kyc-v3.json-ld",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                      "testdata/httpresp_iden3credential_v2.json",
				"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":   "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
				"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/105": "testdata/httpresp_rev_status_105.json",
			})()

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
		})()

		doTest(t, "atomic_query_sig_v2_non_merklized_inputs.json",
			"atomic_query_sig_v2_non_merklized_output.json",
			AtomicQuerySigV2InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQuerySigV2InputsFromJson NonMerklized - missing credentialSubject",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
			})()

			doTest(t, "atomic_query_sig_v2_non_merklized_noop_inputs.json", "",
				AtomicQuerySigV2InputsFromJson, nil, EnvConfig{}, "credentialSubject field is not found in query")
		})

	t.Run("AtomicQuerySigV2InputsFromJson NonMerklized Disclosure",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3-non-merklized.json-ld":                                                "testdata/httpresp_kyc-v3-non-merklized.json-ld",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                  "testdata/httpresp_iden3credential_v2.json",
			})()

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
			})()

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
			})()

			doTest(t,
				"atomic_query_mtp_v2_on_chain_input.json",
				"atomic_query_mtp_v2_on_chain_output.json",
				AtomicQueryMtpV2OnChainInputsFromJson, nil, EnvConfig{}, "")
		})

	t.Run("AtomicQuerySigV2InputsFromJson__RHS__empty_revocation_tree",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				`http://localhost:8545%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0xb4bdea55000d5228592025eac998034e2c03f242819d84806687a3b0c95eefa295ca1202","to":"0x6f0a444df4d231d85f66e4836f836034f0fefe24"},"latest"]}`: "testdata/httpresp_eth_resp1.json",
				"http://localhost:8003/node/8ef2ce21e01d86ec2376fe28bf6b47a84d08f8628d970474a2698cebf94bca1c":                "testdata/httpresp_rhs_8ef2ce21e01d86ec2376fe28bf6b47a84d08f8628d970474a2698cebf94bca1c.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
			})()

			cfg := EnvConfig{
				ChainConfigs: map[core.ChainID]ChainConfig{
					80001: {
						RPCUrl: "http://localhost:8545",
						StateContractAddr: common.HexToAddress(
							"0x6F0a444Df4d231D85F66e4836f836034F0feFE24"),
					},
				},
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
			})()

			cfg := EnvConfig{
				ChainConfigs: map[core.ChainID]ChainConfig{
					80001: {
						RPCUrl: "http://localhost:8545",
						StateContractAddr: common.HexToAddress(
							"0x6F0a444Df4d231D85F66e4836f836034F0feFE24"),
					},
				},
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
			})()

			cfg := EnvConfig{
				ChainConfigs: map[core.ChainID]ChainConfig{
					80001: {
						RPCUrl: "http://localhost:8545",
						StateContractAddr: common.HexToAddress(
							"0x6F0a444Df4d231D85F66e4836f836034F0feFE24"),
					},
				},
			}
			doTest(t, "atomic_query_sig_v2_merklized_rhs_revoked_inputs.json",
				"", AtomicQuerySigV2InputsFromJson, nil, cfg,
				"credential status error: credential is revoked")
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
		})()

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
		})()

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
		})()

		doTest(t, "atomic_query_v3_sig_inputs.json",
			"atomic_query_v3_sig_output.json",
			AtomicQueryV3InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryV3InputsFromJson - empty query", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
		})()

		doTest(t, "atomic_query_v3_sig_empty_query_inputs.json",
			"atomic_query_v3_sig_empty_query_output.json",
			AtomicQueryV3InputsFromJson, nil, EnvConfig{}, "")
	})

	// Inputs does not include proof type, but the query has both. Choose MTP.
	t.Run("AtomicQueryV3InputsFromJson - No proof type, Have both", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
		})()

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
		})()

		doTest(t, "atomic_query_v3_no_proof_type_sig_only_inputs.json",
			"atomic_query_v3_sig_output.json",
			AtomicQueryV3InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryV3OnChainInputsFromJson - MTP", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/3972757": "testdata/httpresp_rev_status_3972757.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                           "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                               "testdata/httpresp_iden3credential_v2.json",
		})()

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
		})()

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
		})()

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
		})()

		doTest(t, "atomic_query_v3_on_chain_tx_data_inputs.json",
			"atomic_query_v3_on_chain_tx_data_output.json",
			AtomicQueryV3OnChainInputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryV3InputsFromJson__Sig_exists_true", func(t *testing.T) {
		ipfsURL := os.Getenv("IPFS_URL")
		if ipfsURL == "" {
			t.Skip("IPFS_URL is not set")
		}

		defer preserveIPFSHttpCli()()

		cid := uploadIPFSFile(t, ipfsURL, "testdata/ipfs_QmcvoKLc742CyVH2Cnw6X95b4c8VdABqNPvTyAHEeaK1aP.json")
		require.Equal(t, "QmcvoKLc742CyVH2Cnw6X95b4c8VdABqNPvTyAHEeaK1aP", cid)

		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld": "testdata/httpresp_iden3proofs.jsonld",
			`http://127.0.0.1:8545%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0xb4bdea55000e02195fa99cf8975171e88a411bff99da7548cd4576ba2d102cf77ec31202","to":"0x134b1be34911e39a8397ec6289782989729807a4"},"latest"]}`: "testdata/httpresp_eth_resp3.json",
			"https://rhs-staging.polygonid.me/node/34f9500218a054d58347b848dae17d07602b9320143c79e2786ff3aa97254f29": "testdata/httpresp_rhs_34f9500218a054d58347b848dae17d07602b9320143c79e2786ff3aa97254f29.json",
			"https://rhs-staging.polygonid.me/node/d469d1307ba23faae8eef13d90031c981e4d2c36977b0422e669e5ef7b891205": "testdata/httpresp_rhs_d469d1307ba23faae8eef13d90031c981e4d2c36977b0422e669e5ef7b891205.json",
			"https://rhs-staging.polygonid.me/node/20b66d667fe760963e023546deaec3550e51cf371c5b03e9eb751b7455601225": "testdata/httpresp_rhs_20b66d667fe760963e023546deaec3550e51cf371c5b03e9eb751b7455601225.json",
			"https://rhs-staging.polygonid.me/node/81e7bed726f2bd88390e9537975e88835094176ad1d350b716d9d3eaaa4da128": "testdata/httpresp_rhs_81e7bed726f2bd88390e9537975e88835094176ad1d350b716d9d3eaaa4da128.json",
			"https://rhs-staging.polygonid.me/node/0aab94d5a794dbb99bcd1ab80e91fef9afb2f9d667244b04ab6820c77dabeb23": "testdata/httpresp_rhs_0aab94d5a794dbb99bcd1ab80e91fef9afb2f9d667244b04ab6820c77dabeb23.json",
			"https://rhs-staging.polygonid.me/node/003177fe2a5c4a9356894d6abb4f0a6da2fb19095e47d2447127edb8f7d01729": "testdata/httpresp_rhs_003177fe2a5c4a9356894d6abb4f0a6da2fb19095e47d2447127edb8f7d01729.json",
			"https://rhs-staging.polygonid.me/node/adb8edf5bffb7168171e33696399d8766a03802624225ce20005cf61753d0611": "testdata/httpresp_rhs_adb8edf5bffb7168171e33696399d8766a03802624225ce20005cf61753d0611.json",
			"https://rhs-staging.polygonid.me/node/c5b8691380634bd9c0f928da490f684579a2b51de1ee52028b74d83f461d0208": "testdata/httpresp_rhs_c5b8691380634bd9c0f928da490f684579a2b51de1ee52028b74d83f461d0208.json",
			"https://rhs-staging.polygonid.me/node/1aefa6dd321a42685112bf762d7dc17a6fb51e5521a819f6d5c8a09681932913": "testdata/httpresp_rhs_1aefa6dd321a42685112bf762d7dc17a6fb51e5521a819f6d5c8a09681932913.json",
			"https://rhs-staging.polygonid.me/node/d2e4c97c4fc3e83521a8b7910765ac62a7171f9120be3c3b854d48cd510e6f0a": "testdata/httpresp_rhs_d2e4c97c4fc3e83521a8b7910765ac62a7171f9120be3c3b854d48cd510e6f0a.json",
		})()

		cfg := EnvConfig{
			IPFSNodeURL: ipfsURL,
			ChainConfigs: map[core.ChainID]ChainConfig{
				80001: {
					RPCUrl: "http://127.0.0.1:8545",
					StateContractAddr: common.HexToAddress(
						"0x134B1BE34911E39A8397ec6289782989729807a4"),
				},
			},
		}

		doTest(t, "atomic_query_v3_sig_exists_true_inputs.json",
			"atomic_query_v3_sig_exists_true_output.json",
			AtomicQueryV3InputsFromJson, nil, cfg, "")
	})

	t.Run("AtomicQueryV3InputsFromJson__Sig_exists_false", func(t *testing.T) {
		ipfsURL := os.Getenv("IPFS_URL")
		if ipfsURL == "" {
			t.Skip("IPFS_URL is not set")
		}

		defer preserveIPFSHttpCli()()

		cid := uploadIPFSFile(t, ipfsURL, "testdata/ipfs_QmcvoKLc742CyVH2Cnw6X95b4c8VdABqNPvTyAHEeaK1aP.json")
		require.Equal(t, "QmcvoKLc742CyVH2Cnw6X95b4c8VdABqNPvTyAHEeaK1aP", cid)

		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld": "testdata/httpresp_iden3proofs.jsonld",
			`http://127.0.0.1:8545%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0xb4bdea55000e02195fa99cf8975171e88a411bff99da7548cd4576ba2d102cf77ec31202","to":"0x134b1be34911e39a8397ec6289782989729807a4"},"latest"]}`: "testdata/httpresp_eth_resp3.json",
			"https://rhs-staging.polygonid.me/node/34f9500218a054d58347b848dae17d07602b9320143c79e2786ff3aa97254f29": "testdata/httpresp_rhs_34f9500218a054d58347b848dae17d07602b9320143c79e2786ff3aa97254f29.json",
			"https://rhs-staging.polygonid.me/node/d469d1307ba23faae8eef13d90031c981e4d2c36977b0422e669e5ef7b891205": "testdata/httpresp_rhs_d469d1307ba23faae8eef13d90031c981e4d2c36977b0422e669e5ef7b891205.json",
			"https://rhs-staging.polygonid.me/node/20b66d667fe760963e023546deaec3550e51cf371c5b03e9eb751b7455601225": "testdata/httpresp_rhs_20b66d667fe760963e023546deaec3550e51cf371c5b03e9eb751b7455601225.json",
			"https://rhs-staging.polygonid.me/node/81e7bed726f2bd88390e9537975e88835094176ad1d350b716d9d3eaaa4da128": "testdata/httpresp_rhs_81e7bed726f2bd88390e9537975e88835094176ad1d350b716d9d3eaaa4da128.json",
			"https://rhs-staging.polygonid.me/node/0aab94d5a794dbb99bcd1ab80e91fef9afb2f9d667244b04ab6820c77dabeb23": "testdata/httpresp_rhs_0aab94d5a794dbb99bcd1ab80e91fef9afb2f9d667244b04ab6820c77dabeb23.json",
			"https://rhs-staging.polygonid.me/node/003177fe2a5c4a9356894d6abb4f0a6da2fb19095e47d2447127edb8f7d01729": "testdata/httpresp_rhs_003177fe2a5c4a9356894d6abb4f0a6da2fb19095e47d2447127edb8f7d01729.json",
			"https://rhs-staging.polygonid.me/node/adb8edf5bffb7168171e33696399d8766a03802624225ce20005cf61753d0611": "testdata/httpresp_rhs_adb8edf5bffb7168171e33696399d8766a03802624225ce20005cf61753d0611.json",
			"https://rhs-staging.polygonid.me/node/c5b8691380634bd9c0f928da490f684579a2b51de1ee52028b74d83f461d0208": "testdata/httpresp_rhs_c5b8691380634bd9c0f928da490f684579a2b51de1ee52028b74d83f461d0208.json",
			"https://rhs-staging.polygonid.me/node/1aefa6dd321a42685112bf762d7dc17a6fb51e5521a819f6d5c8a09681932913": "testdata/httpresp_rhs_1aefa6dd321a42685112bf762d7dc17a6fb51e5521a819f6d5c8a09681932913.json",
			"https://rhs-staging.polygonid.me/node/d2e4c97c4fc3e83521a8b7910765ac62a7171f9120be3c3b854d48cd510e6f0a": "testdata/httpresp_rhs_d2e4c97c4fc3e83521a8b7910765ac62a7171f9120be3c3b854d48cd510e6f0a.json",
		}, httpmock.IgnoreUntouchedURLs())()

		cfg := EnvConfig{
			IPFSNodeURL: ipfsURL,
			ChainConfigs: map[core.ChainID]ChainConfig{
				80001: {
					RPCUrl: "http://127.0.0.1:8545",
					StateContractAddr: common.HexToAddress(
						"0x134B1BE34911E39A8397ec6289782989729807a4"),
				},
			},
		}

		doTest(t, "atomic_query_v3_sig_exists_false_inputs.json",
			"atomic_query_v3_sig_exists_false_output.json",
			AtomicQueryV3InputsFromJson, nil, cfg, "")
	})

	t.Run("AtomicQuerySigV2Inputs Empty roots in state", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai" +
				"%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata" +
				"/httpresp_rev_status_2376431481_empty_rev_root.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0": "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0_empty_roots.json",
		})()

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

	t.Run("AtomicQueryMtpV2InputsFromJson Empty roots in state",
		func(t *testing.T) {
			defer httpmock.MockHTTPClient(t, map[string]string{
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                 "testdata/httpresp_iden3credential_v2.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3-non-merklized.json-ld":                                               "testdata/httpresp_kyc-v3-non-merklized.json-ld",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9/claims/revocation/status/118023115": "testdata/httpresp_rev_status_118023115_empty_roots.json",
			})()

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

	t.Run("LinkedMultiQueryInputsFromJson_Merklized", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
		})()

		doTest(t, "linked_multi_query_inputs.json",
			"linked_multi_query_output.json",
			LinkedMultiQueryInputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("LinkedMultiQueryInputsFromJson_NonMerklized", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3-non-merklized.json-ld":                                                "testdata/httpresp_kyc-v3-non-merklized.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                  "testdata/httpresp_iden3credential_v2.json",
		})()

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
			"linked_multi_query_non_merklized_inputs.json",
			"linked_multi_query_non_merklized_output.json",
			LinkedMultiQueryInputsFromJson, wantVerifiablePresentation,
			EnvConfig{}, "")
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
			in:    `{}`,
			want:  EnvConfig{},
		},
		{
			title: "ipfs node",
			in: `{
  "ipfsNodeUrl": "http://localhost:5001"
}`,
			want: EnvConfig{
				IPFSNodeURL: "http://localhost:5001",
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
				IPFSNodeURL:       "http://localhost:5001",
				EthereumURL:       "http://localhost:8545",
				StateContractAddr: "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655",
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

	if ts, ok := inputsObj["timestamp"]; ok {
		wantObj["timestamp"] = ts
	}

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

func stringFromJsonObj(obj map[string]any, key string) string {
	v, ok := obj[key].(string)
	if ok {
		return v
	}
	return ""
}

func flushCacheDB(t testing.TB) {
	require.NoError(t, getTestCacheDB(t).DropAll())
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
	mockBadgerLog(t)

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

	cacheDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	defer os.RemoveAll(cacheDir)

	mz, err := merklizeCred(ctx, w3cCred, documentLoader, true, cacheDir)
	require.NoError(t, err)
	require.Equal(t, wantRoot, mz.Root().BigInt().String())

	// 3 calls per URL scheme: first for concurrent pre-download schema to put
	// it in cache, second for normalization, and last for compaction
	require.Equal(t, 9, documentLoader.counter())

	// test that following call to merklizeCred does not make any HTTP calls
	documentLoader.reset()

	mz, err = merklizeCred(ctx, w3cCred, documentLoader, true, cacheDir)
	require.NoError(t, err)
	require.Equal(t, wantRoot, mz.Root().BigInt().String())
	require.Equal(t, 0, documentLoader.counter())
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
	mockBadgerLog(t)
	flushCacheDB(t)

	defer httpmock.MockHTTPClient(t, map[string]string{
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
	}, httpmock.IgnoreUntouchedURLs())()

	in := readFixtureFile("atomic_query_mtp_v2_inputs.json")
	cfg := EnvConfig{}
	err := PreCacheVC(context.Background(), cfg, in)
	require.NoError(t, err)

	db := getTestCacheDB(t)

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

func bi(in string) *big.Int {
	i, ok := new(big.Int).SetString(in, 10)
	if !ok {
		panic(in)
	}
	return i
}

func TestUnpackOperatorWithArgs(t *testing.T) {
	op, vals, err := unpackOperatorWithArgs("$exists", true, ld.XSDString,
		merklize.PoseidonHasher{})
	require.NoError(t, err)
	require.Equal(t, circuits.EXISTS, op)
	require.Equal(t, []*big.Int{bi("1")}, vals)

	op, vals, err = unpackOperatorWithArgs("$exists", false, ld.XSDString,
		merklize.PoseidonHasher{})
	require.NoError(t, err)
	require.Equal(t, circuits.EXISTS, op)
	require.Equal(t, []*big.Int{bi("0")}, vals)

	_, _, err = unpackOperatorWithArgs("$exists", "true", ld.XSDString,
		merklize.PoseidonHasher{})
	require.EqualError(t, err, "$exists operator value is not a boolean")
}

func TestDescribeID(t *testing.T) {
	in := `{"id":"31Akw5AB2xBrwqmbDUA2XoSGCfTepz52q9jmFE4mXA"}`

	ctx := context.Background()

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

	resp, err := DescribeID(ctx, cfg, []byte(in))
	require.NoError(t, err)
	wantResp := DescribeIDResponse{
		DID:     "did:polygonid:linea:testnet:31Akw5AB2xBrwqmbDUA2XoSGCfTepz52q9jmFE4mXA",
		ID:      "31Akw5AB2xBrwqmbDUA2XoSGCfTepz52q9jmFE4mXA",
		IDAsInt: "24460059377712687587111979692736628604804094576108957842967948238113620738",
	}
	require.Equal(t, wantResp, resp)

	in = `{"idAsInt":"24460059377712687587111979692736628604804094576108957842967948238113620738"}`
	resp, err = DescribeID(ctx, cfg, []byte(in))
	require.NoError(t, err)
	require.Equal(t, wantResp, resp)

	in = `{
  "id":"31Akw5AB2xBrwqmbDUA2XoSGCfTepz52q9jmFE4mXA",
  "idAsInt":"24460059377712687587111979692736628604804094576108957842967948238113620738"
}`
	resp, err = DescribeID(ctx, cfg, []byte(in))
	require.NoError(t, err)
	require.Equal(t, wantResp, resp)

	in = `{
  "idAsInt":"24460059377712687587111979692736628604804094576108957842967948238113620739"
}`
	_, err = DescribeID(ctx, cfg, []byte(in))
	require.EqualError(t, err, "failed to create ID from int: IDFromBytes error: checksum error")

	in = `{
  "id":"2qMJFBiKaPx3XCKbu1Q45QNaUfdpzk9KkcmNaiyAxc",
  "idAsInt":"24460059377712687587111979692736628604804094576108957842967948238113620738"
}`
	_, err = DescribeID(ctx, cfg, []byte(in))
	require.EqualError(t, err, "id and idAsInt are different")
}

func TestMkVPObj(t *testing.T) {
	const tp = "tp"

	testCases := []struct {
		in      []objEntry
		want    jsonObj
		wantErr string
	}{
		{
			in:      []objEntry{{}},
			wantErr: "empty key",
		},
		{
			in:   []objEntry{},
			want: jsonObj{"@type": tp},
		},
		{
			in: []objEntry{
				{"x.y1.z1", 3},
				{"x.y1.z2", 4},
				{"x.y2", 5},
			},
			want: jsonObj{
				"@type": "tp",
				"x": jsonObj{
					"y1": jsonObj{
						"z1": 3,
						"z2": 4,
					},
					"y2": 5,
				},
			},
		},
		{
			in: []objEntry{
				{"x.y1.z1", 3},
				{"x.y1.z2", 4},
				{"x.y1", 5},
			},
			wantErr: "key already exists: y1",
		},
		{
			in: []objEntry{
				{"x.y1", 5},
				{"x.y1.z1", 3},
				{"x.y1.z2", 4},
			},
			wantErr: "not a json object: y1",
		},
	}

	for i, tc := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			out, err := mkVPObj(tp, tc.in...)
			if tc.wantErr != "" {
				require.EqualError(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.want, out)
		})
	}
}

func TestNewGenesysIDFromEth(t *testing.T) {
	in := `{
  "ethAddress":"0x850174569F4FeDEdFFF12F112602d3FDAcb9e21B",
  "blockchain":"polygon",
  "network":"mumbai",
  "method":"polygonid"
}`

	ctx := context.Background()

	resp, err := NewGenesysIDFromEth(ctx, EnvConfig{}, []byte(in))
	require.NoError(t, err)
	wantResp := GenesysIDResponse{
		DID:     "did:polygonid:polygon:mumbai:2qCU58EJgrELzewx3jhSWLDDdunCaWCAuKVgz7GmyK",
		ID:      "2qCU58EJgrELzewx3jhSWLDDdunCaWCAuKVgz7GmyK",
		IDAsInt: "18925340278420228466712879433563154448903652530982176890458034425491886594",
	}
	require.Equal(t, wantResp, resp)
}

func TestW3cCredentialsFromAnonAadhaarInputsJson(t *testing.T) {
	defer httpmock.MockHTTPClient(t, map[string]string{})()

	ctx := context.Background()
	var cfg EnvConfig
	w3cCred, err := W3cCredentialsFromAnonAadhaarInputsJson(ctx, cfg,
		readFixtureFile("anon_aadhaar_v1_inputs.json"))
	require.NoError(t, err)

	expectedCredential := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
    "ipfs://QmZbsTnRwtCmbdg3r9o7Txid37LmvPcvmzVi1Abvqu1WKL"
  ],
  "type": [
    "VerifiableCredential",
    "BasicPerson"
  ],
  "expirationDate": "2019-09-06T19:54:00Z",
  "issuanceDate": "2019-03-08T05:30:00Z",
  "credentialSubject": {
    "addresses": {
      "primaryAddress": {
        "addressLine1": "C/O Ishwar Chand;East Delhi;;B-31, 3rd Floor;;110051;Krishna Nagar;Delhi;Radhey Shyam Park Extension;Gandhi Nagar;Krishna Nagar"
      }
    },
    "dateOfBirth": 19840101,
    "fullName": "Sumit Kumar",
    "gender": "M",
    "governmentIdentifier": "269720190308114407437",
    "governmentIdentifierType": "other",
    "id": "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G",
	"nationalities": {
		"nationality2CountryCode": "IND"
	},
    "type": "BasicPerson"
  },
  "credentialStatus": {
    "id": "did:iden3:privado:main:2Si3eZUE6XetYsmU5dyUK2Cvaxr1EEe65vdv2BML4L/credentialStatus?revocationNonce=1051565438&contractAddress=80001:0x2fCE183c7Fbc4EbB5DB3B0F5a63e0e02AE9a85d2",
    "type": "Iden3OnchainSparseMerkleTreeProof2023",
    "revocationNonce": 1257894000
  },
  "issuer": "did:iden3:privado:main:2Si3eZUE6XetYsmU5dyUK2Cvaxr1EEe65vdv2BML4L",
  "credentialSchema": {
    "id": "ipfs://QmTojMfyzxehCJVw7aUrdWuxdF68R7oLYooGHCUr9wwsef",
    "type": "JsonSchema2023"
  }
}`
	w3cCred.ID = "" // It's random generated UUID
	w3cCredJ, err := json.Marshal(w3cCred)
	t.Log(string(w3cCredJ))
	require.NoError(t, err)
	require.JSONEq(t, expectedCredential, string(w3cCredJ))
}

func TestW3cCredentialsFromPassportInputsJson(t *testing.T) {
	defer httpmock.MockHTTPClient(t, map[string]string{})()

	ctx := context.Background()
	var cfg EnvConfig
	w3cCred, err := W3cCredentialsFromPassportInputsJson(ctx, cfg,
		readFixtureFile("passport_v1_inputs.json"))
	require.NoError(t, err)

	expectedCredential := `{
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
    "ipfs://QmZbsTnRwtCmbdg3r9o7Txid37LmvPcvmzVi1Abvqu1WKL"
  ],
  "type": [
    "VerifiableCredential",
    "BasicPerson"
  ],
  "expirationDate": "2026-03-21T17:28:52Z",
  "issuanceDate": "2025-03-21T17:28:52Z",
  "credentialSubject": {
    "dateOfBirth": 19960309,
    "documentExpirationDate": 20350803,
    "fullName": "KUZNETSOV  VALERIY",
    "governmentIdentifier": "AC1234567",
    "governmentIdentifierType": "P",
    "id": "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G",
    "nationalities": {
      "nationality1CountryCode": "UKR",
      "nationality2CountryCode": "UKR"
    },
    "sex": "M",
    "type": "BasicPerson"
  },
  "credentialStatus": {
    "id": "did:iden3:privado:main:2Scn2RfosbkQDMQzQM5nCz3Nk5GnbzZCWzGCd3tc2G/credentialStatus?contractAddress=80001:0x2fCE183c7Fbc4EbB5DB3B0F5a63e0e02AE9a85d2\u0026state=a1abdb9f44c7b649eb4d21b59ef34bd38e054aa3e500987575a14fc92c49f42c",
    "type": "Iden3OnchainSparseMerkleTreeProof2023",
    "revocationNonce": 1257894000
  },
  "issuer": "did:iden3:privado:main:2Si3eZUE6XetYsmU5dyUK2Cvaxr1EEe65vdv2BML4L",
  "credentialSchema": {
    "id": "ipfs://QmTojMfyzxehCJVw7aUrdWuxdF68R7oLYooGHCUr9wwsef",
    "type": "JsonSchema2023"
  }
}`
	w3cCred.ID = "" // It's random generated UUID
	w3cCredJ, err := json.Marshal(w3cCred)
	t.Log(string(w3cCredJ))
	require.NoError(t, err)
	require.JSONEq(t, expectedCredential, string(w3cCredJ))

}

func TestW3CCredentialToCoreClaim_no_options(t *testing.T) {
	in := []byte(`{
"w3cCredential": {
  "id": "urn:iden3:onchain:80001:0xc84e8ac5385E0813f01aA9C698ED44C831961670:0",
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
    "https://gist.githubusercontent.com/ilya-korotya/660496c859f8d31a7d2a92ca5e970967/raw/6b5fc14fe630c17bfa52e05e08fdc8394c5ea0ce/non-merklized-non-zero-balance.jsonld",
    "https://schema.iden3.io/core/jsonld/displayMethod.jsonld"
  ],
  "type": [
    "VerifiableCredential",
    "Balance"
  ],
  "expirationDate": "2024-03-23T11:05:26Z",
  "issuanceDate": "2024-02-22T11:05:26Z",
  "credentialSubject": {
    "address": "657065114158124047812701241180089030040156354062",
    "balance": "174130123440549329",
    "id": "did:polygonid:polygon:mumbai:2qJFtKfABTJi2yUAcUhuvUnDojuNwUJjhuXQDhUg3e",
    "type": "Balance"
  },
  "credentialStatus": {
    "id": "did:polygonid:polygon:mumbai:2qCU58EJgrEMJvPfhUCnFCwuKQTkX8VmJX2sJCH6C8/credentialStatus?revocationNonce=0\u0026contractAddress=80001:0xc84e8ac5385E0813f01aA9C698ED44C831961670",
    "type": "Iden3OnchainSparseMerkleTreeProof2023",
    "revocationNonce": 0
  },
  "issuer": "did:polygonid:polygon:mumbai:2qCU58EJgrEMJvPfhUCnFCwuKQTkX8VmJX2sJCH6C8",
  "credentialSchema": {
    "id": "https://gist.githubusercontent.com/ilya-korotya/e10cd79a8cc26ab6e40400a11838617e/raw/575edc33d485e2a4c806baad97e21117f3c90a9f/non-merklized-non-zero-balance.json",
    "type": "JsonSchema2023"
  },
  "proof": [
    {
      "type": "Iden3SparseMerkleTreeProof",
      "issuerData": {
        "id": "did:polygonid:polygon:mumbai:2qCU58EJgrEMJvPfhUCnFCwuKQTkX8VmJX2sJCH6C8",
        "state": {
          "rootOfRoots": "19a633fecfa2117672bbcfb65307e3bd73101cd3dd49b849ea231b5927afc70e",
          "claimsTreeRoot": "3ca701ead4d7da0eb5c4950ac0950a7ae92f4acc853a24698489f5a9b08fc72e",
          "revocationTreeRoot": "0000000000000000000000000000000000000000000000000000000000000000",
          "value": "6f5dd91f13004cca5c8b31524239de77ce149a9073d7ace737a1b7cffb96ab26"
        }
      },
      "coreClaim": "f52f1795c533d7b4aa4e7ab02485f86f0a00000000000000000000000000000002127f89ff6f78c9637e437575d1123c3862b93876abb197b010ea1dad600d000eb6cb518d3dd33341899bcec9dcc68998d11773000000000000000000000000d16d5eb86ca26a02000000000000000000000000000000000000000000000000000000000000000076b7fe650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "mtp": {
        "existence": true,
        "siblings": [
          "4692761366944891051814480185546124875872606319832740381039122455881379612023"
        ]
      }
    }
  ],
  "displayMethod": {
    "id": "ipfs://QmS8eY8ZCiAAW8qgx3T6SQ3HDGeddwLZsjPXNAZExQwRY4",
    "type": "Iden3BasicDisplayMethodV1"
  }
}
}`)

	cfg := cfgWithCacheDir(t, EnvConfig{})
	resp, err := W3CCredentialToCoreClaim(context.Background(), cfg, in)
	require.NoError(t, err)

	j, err := json.Marshal(resp)
	require.NoError(t, err)

	want := `{
"coreClaim":[
  "3551658366829735292135739573638798979061",
  "23636246712529601958450231201481253153358313547226024401161643230341566978",
  "657065114158124047812701241180089030040156354062",
  "174130123440549329",
  "31565919519920133594379452416","0","0","0"
],
"coreClaimHex":"f52f1795c533d7b4aa4e7ab02485f86f0a00000000000000000000000000000002127f89ff6f78c9637e437575d1123c3862b93876abb197b010ea1dad600d000eb6cb518d3dd33341899bcec9dcc68998d11773000000000000000000000000d16d5eb86ca26a02000000000000000000000000000000000000000000000000000000000000000076b7fe650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
"coreClaimHIndex":"9830186757367035399211680064143074011271741678904507974796272761508415159201",
"coreClaimHValue":"17258652693603475311237387771556096220921552146872585410863362205406628125367"
}`
	require.JSONEq(t, want, string(j))
}

func TestW3CCredentialToCoreClaim_with_options(t *testing.T) {
	in := []byte(`{
"w3cCredential": {
  "id": "urn:iden3:onchain:80001:0xc84e8ac5385E0813f01aA9C698ED44C831961670:0",
  "@context": [
    "https://www.w3.org/2018/credentials/v1",
    "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld",
    "https://gist.githubusercontent.com/ilya-korotya/660496c859f8d31a7d2a92ca5e970967/raw/6b5fc14fe630c17bfa52e05e08fdc8394c5ea0ce/non-merklized-non-zero-balance.jsonld",
    "https://schema.iden3.io/core/jsonld/displayMethod.jsonld"
  ],
  "type": [
    "VerifiableCredential",
    "Balance"
  ],
  "expirationDate": "2024-03-23T11:05:26Z",
  "issuanceDate": "2024-02-22T11:05:26Z",
  "credentialSubject": {
    "address": "657065114158124047812701241180089030040156354062",
    "balance": "174130123440549329",
    "id": "did:polygonid:polygon:mumbai:2qJFtKfABTJi2yUAcUhuvUnDojuNwUJjhuXQDhUg3e",
    "type": "Balance"
  },
  "credentialStatus": {
    "id": "did:polygonid:polygon:mumbai:2qCU58EJgrEMJvPfhUCnFCwuKQTkX8VmJX2sJCH6C8/credentialStatus?revocationNonce=0\u0026contractAddress=80001:0xc84e8ac5385E0813f01aA9C698ED44C831961670",
    "type": "Iden3OnchainSparseMerkleTreeProof2023",
    "revocationNonce": 0
  },
  "issuer": "did:polygonid:polygon:mumbai:2qCU58EJgrEMJvPfhUCnFCwuKQTkX8VmJX2sJCH6C8",
  "credentialSchema": {
    "id": "https://gist.githubusercontent.com/ilya-korotya/e10cd79a8cc26ab6e40400a11838617e/raw/575edc33d485e2a4c806baad97e21117f3c90a9f/non-merklized-non-zero-balance.json",
    "type": "JsonSchema2023"
  },
  "proof": [
    {
      "type": "Iden3SparseMerkleTreeProof",
      "issuerData": {
        "id": "did:polygonid:polygon:mumbai:2qCU58EJgrEMJvPfhUCnFCwuKQTkX8VmJX2sJCH6C8",
        "state": {
          "rootOfRoots": "19a633fecfa2117672bbcfb65307e3bd73101cd3dd49b849ea231b5927afc70e",
          "claimsTreeRoot": "3ca701ead4d7da0eb5c4950ac0950a7ae92f4acc853a24698489f5a9b08fc72e",
          "revocationTreeRoot": "0000000000000000000000000000000000000000000000000000000000000000",
          "value": "6f5dd91f13004cca5c8b31524239de77ce149a9073d7ace737a1b7cffb96ab26"
        }
      },
      "coreClaim": "f52f1795c533d7b4aa4e7ab02485f86f0a00000000000000000000000000000002127f89ff6f78c9637e437575d1123c3862b93876abb197b010ea1dad600d000eb6cb518d3dd33341899bcec9dcc68998d11773000000000000000000000000d16d5eb86ca26a02000000000000000000000000000000000000000000000000000000000000000076b7fe650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
      "mtp": {
        "existence": true,
        "siblings": [
          "4692761366944891051814480185546124875872606319832740381039122455881379612023"
        ]
      }
    }
  ],
  "displayMethod": {
    "id": "ipfs://QmS8eY8ZCiAAW8qgx3T6SQ3HDGeddwLZsjPXNAZExQwRY4",
    "type": "Iden3BasicDisplayMethodV1"
  }
},
"coreClaimOptions": {
  "revNonce": 100500,
  "version": 10
}
}`)

	cfg := cfgWithCacheDir(t, EnvConfig{})
	resp, err := W3CCredentialToCoreClaim(context.Background(), cfg, in)
	require.NoError(t, err)

	j, err := json.Marshal(resp)
	require.NoError(t, err)

	want := `{
"coreClaim":[
  "14615016376860687548866583619298569770198124408821",
  "23636246712529601958450231201481253153358313547226024401161643230341566978",
  "657065114158124047812701241180089030040156354062",
  "174130123440549329",
  "31565919519920133594379552916","0","0","0"
],
"coreClaimHex":"f52f1795c533d7b4aa4e7ab02485f86f0a0000000a000000000000000000000002127f89ff6f78c9637e437575d1123c3862b93876abb197b010ea1dad600d000eb6cb518d3dd33341899bcec9dcc68998d11773000000000000000000000000d16d5eb86ca26a02000000000000000000000000000000000000000000000000948801000000000076b7fe650000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
"coreClaimHIndex":"8248879511591962298487070528062416881268611626776654397983770791558299508439",
"coreClaimHValue":"6727479208098822222837416757591595696764728825200049195652465812007399726477"
}`
	require.JSONEq(t, want, string(j))
}

func cfgWithCacheDir(t testing.TB, cfg EnvConfig) EnvConfig {
	cacheDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	t.Cleanup(func() {
		err = os.RemoveAll(cacheDir)
		require.NoError(t, err)
	})

	cfg.CacheDir = cacheDir
	return cfg
}
