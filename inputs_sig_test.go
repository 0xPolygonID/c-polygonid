package c_polygonid

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	shell "github.com/ipfs/go-ipfs-api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var usedHttpResponses = make(map[string]struct{})
var usedHttpResponsesM sync.Mutex

// That that all testdata/httpresp_* files were used. Return non-zero if
// found redundant files.
func checkForRedundantHttpresps() int {
	files, err := os.ReadDir("testdata")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error reading testdata dir: %v\n", err)
		return 1
	}

	usedHttpResponsesM.Lock()
	for _, file := range files {
		fName := file.Name()
		if !strings.HasPrefix(fName, "httpresp_") {
			continue
		}

		_, ok := usedHttpResponses["testdata/"+fName]
		if !ok {
			fmt.Printf("found file %v that were not used in tests\n", fName)
			return 1
		}
	}
	usedHttpResponsesM.Unlock()

	return 0
}

type mockedRouterTripper struct {
	t         testing.TB
	routes    map[string]string
	seenURLsM sync.Mutex
	seenURLs  map[string]struct{}
}

func (m *mockedRouterTripper) RoundTrip(
	request *http.Request) (*http.Response, error) {

	urlStr := request.URL.String()
	routerKey := urlStr
	rr := httptest.NewRecorder()
	var postData []byte
	if request.Method == http.MethodPost {
		var err error
		postData, err = io.ReadAll(request.Body)
		if err != nil {
			http.Error(rr, err.Error(), http.StatusInternalServerError)

			rr2 := rr.Result()
			rr2.Request = request
			return rr2, nil
		}
		if len(postData) > 0 {
			routerKey += "%%%" + string(postData)
		}
	}

	respFile, ok := m.routes[routerKey]
	if !ok {
		var requestBodyStr = string(postData)
		if requestBodyStr == "" {
			m.t.Errorf("unexpected http request: %v", urlStr)
		} else {
			m.t.Errorf("unexpected http request: %v\nBody: %v",
				urlStr, requestBodyStr)
		}
		rr := httptest.NewRecorder()
		rr.WriteHeader(http.StatusNotFound)
		rr2 := rr.Result()
		rr2.Request = request
		return rr2, nil
	}

	m.seenURLsM.Lock()
	if m.seenURLs == nil {
		m.seenURLs = make(map[string]struct{})
	}
	m.seenURLs[routerKey] = struct{}{}
	m.seenURLsM.Unlock()

	usedHttpResponsesM.Lock()
	usedHttpResponses[respFile] = struct{}{}
	usedHttpResponsesM.Unlock()

	http.ServeFile(rr, request, respFile)

	rr2 := rr.Result()
	rr2.Request = request
	return rr2, nil
}

func mockHttpClient(t testing.TB, routes map[string]string) func() {
	oldRoundTripper := httpClient.Transport
	oldRoundTripper2 := http.DefaultTransport
	transport := &mockedRouterTripper{t: t, routes: routes}
	httpClient.Transport = transport
	http.DefaultTransport = transport
	return func() {
		httpClient.Transport = oldRoundTripper
		http.DefaultTransport = oldRoundTripper2

		for u := range routes {
			_, ok := transport.seenURLs[u]
			assert.True(t, ok,
				"found a URL in routes that we did not touch: %v", u)
		}
	}
}

func TestHexHash_UnmarshalJSON(t *testing.T) {
	s := `"2b9d4abe9012cc337d3d347b66659cc45091f822dccb004d88d9f1459e2de306"`
	var h hexHash
	err := h.UnmarshalJSON([]byte(s))
	require.NoError(t, err)
}

func uploadIPFSFile(t testing.TB, ipfsURL string, fName string) string {
	ipfsCli := shell.NewShell(ipfsURL)

	f, err := os.Open(fName)
	require.NoError(t, err)
	// no need to close f

	// Context is a pure file (no directory)
	cid, err := ipfsCli.Add(f)
	require.NoError(t, err)

	return cid
}

func TestPrepareInputs(t *testing.T) {

	type PrepareInputsFn func(
		ctx context.Context, cfg EnvConfig, in []byte) (
		AtomicQueryInputsResponse, error)

	doTest := func(t testing.TB, inFile, wantOutFile string,
		fn PrepareInputsFn, wantVR map[string]any, cfg EnvConfig,
		wantErr string) {

		jsonIn, err := os.ReadFile("testdata/" + inFile)
		require.NoError(t, err)

		ctx := context.Background()
		out, err := fn(ctx, cfg, jsonIn)
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
		defer mockHttpClient(t, map[string]string{
			`http://localhost:8545%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"data":"0x110c96a70008d1b032ae8f736f9e26cd20eab4bf44351a135e05a500000000000000120200000000000000000000000000000000000000000000000000000000291bd4dc","from":"0x0000000000000000000000000000000000000000","to":"0xa5055e131a3544bfb4ea20cd269e6f738fae32b0"},"latest"]}`: "testdata/httpresp_eth_on_chain_status_resp.json",
			"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/cbade52faccea8c386bab0129c0ffffa64393849/core" +
				"/jsonld/iden3proofs.jsonld": "testdata/httpresp_iden3proofs.jsonld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld": "testdata/httpresp_kyc_v4.jsonld",
		})()
		cfg := EnvConfig{
			EthereumURL:       "http://localhost:8545",
			StateContractAddr: common.HexToAddress("0xAD8148c2aB7fe91BD492783a37b9FC2d52B38903"),
		}

		doTest(t, "atomic_query_mtp_v2_on_chain_status_inputs.json",
			"atomic_query_mtp_v2_on_chain_status_output.json", AtomicQueryMtpV2InputsFromJson,
			nil, cfg, "")
	})

	t.Run("AtomicQueryMtpV2InputsFromJson", func(t *testing.T) {
		defer mockHttpClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9/claims/revocation/status/380518664": "testdata/httpresp_rev_status_380518664.json",
			"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
		})()

		doTest(t, "atomic_query_mtp_v2_inputs.json",
			"atomic_query_mtp_v2_output.json", AtomicQueryMtpV2InputsFromJson,
			nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryMtpV2InputsFromJson NonMerklized", func(t *testing.T) {
		defer mockHttpClient(t, map[string]string{
			"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                 "testdata/httpresp_iden3credential_v2.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                             "testdata/httpresp_kyc-v3-non-merklized.json-ld",
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9/claims/revocation/status/118023115": "testdata/httpresp_rev_status_118023115.json",
		})()

		doTest(t, "atomic_query_mtp_v2_non_merklized_inputs.json",
			"atomic_query_mtp_v2_non_merklized_output.json",
			AtomicQueryMtpV2InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQueryMtpV2InputsFromJson NonMerklized Disclosure",
		func(t *testing.T) {
			defer mockHttpClient(t, map[string]string{
				"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                 "testdata/httpresp_iden3credential_v2.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                             "testdata/httpresp_kyc-v3-non-merklized.json-ld",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9/claims/revocation/status/118023115": "testdata/httpresp_rev_status_118023115.json",
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
		defer mockHttpClient(t, map[string]string{
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
			"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
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
		defer mockHttpClient(t, map[string]string{
			"https://www.w3.org/2018/credentials/v1":                                                                                                                 "testdata/httpresp_credentials_v1.json",
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

		cid := uploadIPFSFile(t, ipfsURL, "testdata/httpresp_kyc-v3.json-ld")
		// CID should correspond to the URL from the
		// atomic_query_sig_v2_merklized_ipfs_inputs.json test input.
		require.Equal(t, "QmXwNybNDvsdva11ypERby1nYnR5vJPTy9ZvHdnhaPMD7z", cid)

		defer mockHttpClient(t, map[string]string{
			"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
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
		defer mockHttpClient(t, map[string]string{
			"https://www.w3.org/2018/credentials/v1":                                                                                                                 "testdata/httpresp_credentials_v1.json",
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
		defer mockHttpClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/105": "testdata/httpresp_rev_status_105.json",
		})()

		doTest(t, "atomic_query_sig_v2_merklized_revoked_inputs.json", "",
			AtomicQuerySigV2InputsFromJson, nil, EnvConfig{},
			"credential is revoked")
	})

	t.Run("AtomicQuerySigV2InputsFromJson - skip revocation check",
		func(t *testing.T) {
			defer mockHttpClient(t, map[string]string{
				"https://www.w3.org/2018/credentials/v1":                                                                                                          "testdata/httpresp_credentials_v1.json",
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
		defer mockHttpClient(t, map[string]string{
			"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                  "testdata/httpresp_iden3credential_v2.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                              "testdata/httpresp_kyc-v3-non-merklized.json-ld",
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
		})()

		doTest(t, "atomic_query_sig_v2_non_merklized_inputs.json",
			"atomic_query_sig_v2_non_merklized_output.json",
			AtomicQuerySigV2InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQuerySigV2InputsFromJson NonMerklized - noop",
		func(t *testing.T) {
			defer mockHttpClient(t, map[string]string{
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
			})()

			doTest(t, "atomic_query_sig_v2_non_merklized_noop_inputs.json",
				"atomic_query_sig_v2_non_merklized_noop_output.json",
				AtomicQuerySigV2InputsFromJson, nil, EnvConfig{}, "")
		})

	t.Run("AtomicQuerySigV2InputsFromJson NonMerklized Disclosure",
		func(t *testing.T) {
			defer mockHttpClient(t, map[string]string{
				"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                  "testdata/httpresp_iden3credential_v2.json",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                              "testdata/httpresp_kyc-v3-non-merklized.json-ld",
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
			defer mockHttpClient(t, map[string]string{
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/3972757": "testdata/httpresp_rev_status_3972757.json",
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/0":       "testdata/httpresp_rev_status_qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV_0.json",
				"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
			})()

			doTest(t,
				"atomic_query_sig_v2_on_chain_input.json",
				"atomic_query_sig_v2_on_chain_output.json",
				AtomicQuerySigV2OnChainInputsFromJson, nil, EnvConfig{}, "")
		})

	t.Run("AtomicQueryMtpV2OnChainInputsFromJson",
		func(t *testing.T) {
			defer mockHttpClient(t, map[string]string{
				"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/3972757": "testdata/httpresp_rev_status_3972757.json",
				"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
			})()

			doTest(t,
				"atomic_query_mtp_v2_on_chain_input.json",
				"atomic_query_mtp_v2_on_chain_output.json",
				AtomicQueryMtpV2OnChainInputsFromJson, nil, EnvConfig{}, "")
		})

	t.Run("AtomicQuerySigV2InputsFromJson - RHS - empty revocation tree",
		func(t *testing.T) {
			defer mockHttpClient(t, map[string]string{
				`http://localhost:8545%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"data":"0xb4bdea55000d5228592025eac998034e2c03f242819d84806687a3b0c95eefa295ca1202","from":"0x0000000000000000000000000000000000000000","to":"0x6f0a444df4d231d85f66e4836f836034f0fefe24"},"latest"]}`: "testdata/httpresp_eth_resp1.json",
				"http://localhost:8003/node/8ef2ce21e01d86ec2376fe28bf6b47a84d08f8628d970474a2698cebf94bca1c":                "testdata/httpresp_rhs_8ef2ce21e01d86ec2376fe28bf6b47a84d08f8628d970474a2698cebf94bca1c.json",
				"https://www.w3.org/2018/credentials/v1":                                                                     "testdata/httpresp_credentials_v1.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
			})()

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
			defer mockHttpClient(t, map[string]string{
				`http://localhost:8545%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"data":"0xb4bdea55000d5228592025eac998034e2c03f242819d84806687a3b0c95eefa295ca1202","from":"0x0000000000000000000000000000000000000000","to":"0x6f0a444df4d231d85f66e4836f836034f0fefe24"},"latest"]}`: "testdata/httpresp_eth_resp2.json",
				"http://localhost:8003/node/5ce9b64f8472b094191230e881ed8d85ce215de414b496eb029161c30d654b20":                "testdata/httpresp_rhs_5ce9b64f8472b094191230e881ed8d85ce215de414b496eb029161c30d654b20.json",
				"http://localhost:8003/node/d55bad23c75687c86105589f50612a97ac1904cb0bbc13927a3d6a68321f9f29":                "testdata/httpresp_rhs_d55bad23c75687c86105589f50612a97ac1904cb0bbc13927a3d6a68321f9f29.json",
				"http://localhost:8003/node/95fff1dd8f67374e1eebf9b462a6189517d438883be332bb9f1eb4f41c066014":                "testdata/httpresp_rhs_95fff1dd8f67374e1eebf9b462a6189517d438883be332bb9f1eb4f41c066014.json",
				"http://localhost:8003/node/243781162f6392357e51ea0cc6b1086edcb725e27e747be0839fff8beafd4e2a":                "testdata/httpresp_rhs_243781162f6392357e51ea0cc6b1086edcb725e27e747be0839fff8beafd4e2a.json",
				"http://localhost:8003/node/012cf3eb22da52668f730fee0671b6c1cec67af7ab43c77e3a9d2d4d4a34e323":                "testdata/httpresp_rhs_012cf3eb22da52668f730fee0671b6c1cec67af7ab43c77e3a9d2d4d4a34e323.json",
				"http://localhost:8003/node/7e1415c74c9dacbd81786ab93f3bf50425f10566f96d1bf1a47d7d6218020c2d":                "testdata/httpresp_rhs_7e1415c74c9dacbd81786ab93f3bf50425f10566f96d1bf1a47d7d6218020c2d.json",
				"http://localhost:8003/node/d543edb99a153f54e1338f3c9515bc49ccc4c468433de880c7299b1b0fc16017":                "testdata/httpresp_rhs_d543edb99a153f54e1338f3c9515bc49ccc4c468433de880c7299b1b0fc16017.json",
				"https://www.w3.org/2018/credentials/v1":                                                                     "testdata/httpresp_credentials_v1.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
			})()

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
			defer mockHttpClient(t, map[string]string{
				`http://localhost:8545%%%{"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"data":"0xb4bdea55000d5228592025eac998034e2c03f242819d84806687a3b0c95eefa295ca1202","from":"0x0000000000000000000000000000000000000000","to":"0x6f0a444df4d231d85f66e4836f836034f0fefe24"},"latest"]}`: "testdata/httpresp_eth_resp2.json",
				"http://localhost:8003/node/5ce9b64f8472b094191230e881ed8d85ce215de414b496eb029161c30d654b20": "testdata/httpresp_rhs_5ce9b64f8472b094191230e881ed8d85ce215de414b496eb029161c30d654b20.json",
				"http://localhost:8003/node/d55bad23c75687c86105589f50612a97ac1904cb0bbc13927a3d6a68321f9f29": "testdata/httpresp_rhs_d55bad23c75687c86105589f50612a97ac1904cb0bbc13927a3d6a68321f9f29.json",
				"http://localhost:8003/node/a75cc7f84f279f758427e8f1ec26d2d7dcac0fd545098ef668dde0d2f90ca809": "testdata/httpresp_rhs_a75cc7f84f279f758427e8f1ec26d2d7dcac0fd545098ef668dde0d2f90ca809.json",
				"http://localhost:8003/node/ce051a956948154312d91a406b52120fd689376c1b675699053cc1d7cafa4f04": "testdata/httpresp_rhs_ce051a956948154312d91a406b52120fd689376c1b675699053cc1d7cafa4f04.json",
				"http://localhost:8003/node/3ecaca31559a389adb870fa1347b8487dee24406a7c9959334d3f36b65c3ba1d": "testdata/httpresp_rhs_3ecaca31559a389adb870fa1347b8487dee24406a7c9959334d3f36b65c3ba1d.json",
			})()

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

		cid := uploadIPFSFile(t, ipfsURL, "testdata/ipfs_QmcAJCriUKiU4WQogfhqpi6j8S8XTmZdmg7hpaVr4eGynW.json-ld")
		// CID should correspond to the URL
		require.Equal(t, "QmcAJCriUKiU4WQogfhqpi6j8S8XTmZdmg7hpaVr4eGynW", cid)

		defer mockHttpClient(t, map[string]string{
			"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
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
				ChainConfigs: map[ChainID]ChainConfig{
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
		EthereumURL:       "http://host2.com/default",
		StateContractAddr: common.BytesToAddress([]byte{1}),
	}

	cfg := EnvConfig{
		ChainConfigs: PerChainConfig{
			80001: ChainConfig{
				EthereumURL:       "http://host1.com/mumbai",
				StateContractAddr: common.BytesToAddress([]byte{2}),
			},
		},
		EthereumURL:           defaultChainCfg.EthereumURL,
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
			title:   "full format",
			in:      "http://localhost:8003/node/7e1415c74c9dacbd81786ab93f3bf50425f10566f96d1bf1a47d7d6218020c2d",
			baseURL: "http://localhost:8003/",
			hash:    nil,
			wantErr: "",
		},
		{
			title:   "full format with state",
			in:      "http://localhost:8003/node/7e1415c74c9dacbd81786ab93f3bf50425f10566f96d1bf1a47d7d6218020c2d?state=46a119b1184b2f4256c13633d1f36dc2f489523e14ca4058e1c53324f16a4506",
			baseURL: "http://localhost:8003/",
			hash:    mkHash(t, "46a119b1184b2f4256c13633d1f36dc2f489523e14ca4058e1c53324f16a4506"),
			wantErr: "",
		},
		{
			title:   "error parsing genesis state",
			in:      "http://localhost:8003/node/7e1415c74c9dacbd81786ab93f3bf50425f10566f96d1bf1a47d7d6218020c2d?state=46a119b1184b2f4256c13633d1f36dc2f489523e14ca4058e1c53324f16a45",
			baseURL: "",
			hash:    nil,
			wantErr: "invalid hash length",
		},
		{
			title:   "unsupported url",
			in:      "http://localhost:8003/node1/7e1415c74c9dacbd81786ab93f3bf50425f10566f96d1bf1a47d7d6218020c2d",
			baseURL: "",
			hash:    nil,
			wantErr: "error on parsing the RHS URL: we do not support RHS URLs without /node in the path yet",
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
