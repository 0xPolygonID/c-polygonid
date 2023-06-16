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
	"github.com/iden3/go-circuits"
	"github.com/iden3/go-merkletree-sql/v2"
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
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                             "testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v2.json":                                                      "testdata/httpresp_KYCAgeCredential-v2.json",
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
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                             "testdata/httpresp_kyc-v3.json-ld",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v2.json":                                                      "testdata/httpresp_KYCAgeCredential-v2.json",
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
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc_v3.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
			"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
		})()

		doTest(t, "atomic_query_sig_v2_merklized_inputs.json",
			"atomic_query_sig_v2_merklized_output.json",
			AtomicQuerySigV2InputsFromJson, nil, EnvConfig{}, "")
	})

	t.Run("AtomicQuerySigV2InputsFromJson - noop", func(t *testing.T) {
		defer mockHttpClient(t, map[string]string{
			"https://www.w3.org/2018/credentials/v1":                                                                                                                 "testdata/httpresp_credentials_v1.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc_v3.json",
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
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                  "testdata/httpresp_kyc_v3.json",
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
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                              "testdata/httpresp_kyc-v3.json-ld",
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v2.json":                                                       "testdata/httpresp_KYCAgeCredential-v2.json",
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
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v2.json":                                                       "testdata/httpresp_KYCAgeCredential-v2.json",
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
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v2.json":                                                       "testdata/httpresp_KYCAgeCredential-v2.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                              "testdata/httpresp_kyc-v3.json-ld",
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
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc_v3.json",
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
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc_v3.json",
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
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc_v3.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
			})()

			cfg := EnvConfig{
				EthereumURL: "http://localhost:8545",
				StateContractAddr: common.HexToAddress(
					"0x6F0a444Df4d231D85F66e4836f836034F0feFE24"),
				ReverseHashServiceUrl: "http://localhost:8003",
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
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc_v3.json",
				"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
			})()

			cfg := EnvConfig{
				EthereumURL: "http://localhost:8545",
				StateContractAddr: common.HexToAddress(
					"0x6F0a444Df4d231D85F66e4836f836034F0feFE24"),
				ReverseHashServiceUrl: "http://localhost:8003",
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
				ReverseHashServiceUrl: "http://localhost:8003",
			}
			doTest(t, "atomic_query_sig_v2_merklized_rhs_revoked_inputs.json",
				"", AtomicQuerySigV2InputsFromJson, nil, cfg,
				"credential is revoked")
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
