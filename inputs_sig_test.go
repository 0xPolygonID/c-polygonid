package c_polygonid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/ethereum/go-ethereum/common"
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
	respFile, ok := m.routes[urlStr]
	if !ok {
		m.t.Errorf("unexpected http request: %v", urlStr)
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
	m.seenURLs[urlStr] = struct{}{}
	m.seenURLsM.Unlock()

	usedHttpResponsesM.Lock()
	usedHttpResponses[respFile] = struct{}{}
	usedHttpResponsesM.Unlock()

	rr := httptest.NewRecorder()
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

func TestAtomicQuerySigV2InputsFromJson(t *testing.T) {
	defer mockHttpClient(t, map[string]string{
		"https://www.w3.org/2018/credentials/v1":                                                                                                                 "testdata/httpresp_credentials_v1.json",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                         "testdata/httpresp_kyc_v3.json",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                             "testdata/httpresp_iden3credential_v2.json",
		"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
		"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
	})()

	jsonIn, err := os.ReadFile(
		"testdata/atomic_query_sig_v2_merklized_inputs.json")
	require.NoError(t, err)

	ctx := context.Background()
	var emptyCfg EnvConfig
	out, err := AtomicQuerySigV2InputsFromJson(ctx, emptyCfg, jsonIn)
	require.NoError(t, err)

	inputsBytes, err := out.Inputs.InputsMarshal()
	require.NoError(t, err)

	var inputsObj jsonObj
	err = json.Unmarshal(inputsBytes, &inputsObj)
	require.NoError(t, err)

	jsonWant, err := os.ReadFile(
		"testdata/atomic_query_sig_v2_merklized_output.json")
	require.NoError(t, err)
	var wantObj jsonObj
	err = json.Unmarshal(jsonWant, &wantObj)
	require.NoError(t, err)
	wantObj["timestamp"] = inputsObj["timestamp"]

	require.Equal(t, wantObj, inputsObj, "got: %s", inputsBytes)
}

func TestHexHash_UnmarshalJSON(t *testing.T) {
	s := `"2b9d4abe9012cc337d3d347b66659cc45091f822dccb004d88d9f1459e2de306"`
	var h hexHash
	err := h.UnmarshalJSON([]byte(s))
	require.NoError(t, err)
}

func TestAtomicQueryMtpV2InputsFromJson(t *testing.T) {
	defer mockHttpClient(t, map[string]string{
		"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9/claims/revocation/status/380518664": "testdata/httpresp_rev_status_380518664.json",
		"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
	})()
	jsonIn, err := os.ReadFile("testdata/atomic_query_mtp_v2_inputs.json")
	require.NoError(t, err)

	ctx := context.Background()
	var emptyCfg EnvConfig
	out, err := AtomicQueryMtpV2InputsFromJson(ctx, emptyCfg, jsonIn)
	require.NoError(t, err)

	inputsBytes, err := out.Inputs.InputsMarshal()
	require.NoError(t, err)

	var inputsObj jsonObj
	err = json.Unmarshal(inputsBytes, &inputsObj)
	require.NoError(t, err)

	jsonWant, err := os.ReadFile("testdata/atomic_query_mtp_v2_output.json")
	require.NoError(t, err)
	var wantObj jsonObj
	err = json.Unmarshal(jsonWant, &wantObj)
	require.NoError(t, err)
	wantObj["timestamp"] = inputsObj["timestamp"]

	require.Equal(t, wantObj, inputsObj, "got: %s", inputsBytes)
}

func TestAtomicQueryMtpV2InputsFromJson_NonMerklized(t *testing.T) {
	defer mockHttpClient(t, map[string]string{
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v2.json":                                                      "testdata/httpresp_KYCAgeCredential-v2.json",
		"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qFuKxq6iPem5w2U6T6druwGFjqTinE1kqNkSN7oo9/claims/revocation/status/118023115": "testdata/httpresp_rev_status_118023115.json",
	})()
	jsonIn, err := os.ReadFile("testdata/atomic_query_mtp_v2_non_merklized_inputs.json")
	require.NoError(t, err)

	ctx := context.Background()
	var emptyCfg EnvConfig
	out, err := AtomicQueryMtpV2InputsFromJson(ctx, emptyCfg, jsonIn)
	require.NoError(t, err)

	inputsBytes, err := out.Inputs.InputsMarshal()
	require.NoError(t, err)

	var inputsObj jsonObj
	err = json.Unmarshal(inputsBytes, &inputsObj)
	require.NoError(t, err)

	jsonWant, err := os.ReadFile("testdata/atomic_query_mtp_v2_non_merklized_output.json")
	require.NoError(t, err)
	var wantObj jsonObj
	err = json.Unmarshal(jsonWant, &wantObj)
	require.NoError(t, err)
	wantObj["timestamp"] = inputsObj["timestamp"]

	require.Equal(t, wantObj, inputsObj, "got: %s", inputsBytes)
}

func TestAtomicQuerySigV2InputsFromJson_Disclosure(t *testing.T) {
	defer mockHttpClient(t, map[string]string{
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":             "testdata/httpresp_kyc-v3.json-ld",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld": "testdata/httpresp_iden3credential_v2.json",
		"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
		"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": "testdata/httpresp_rev_status_2376431481.json",
		"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0":          "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
	})()

	jsonIn, err := os.ReadFile(
		"testdata/atomic_query_sig_v2_merklized_disclosure_inputs.json")
	require.NoError(t, err)

	ctx := context.Background()
	var emptyCfg EnvConfig
	out, err := AtomicQuerySigV2InputsFromJson(ctx, emptyCfg, jsonIn)
	require.NoError(t, err)

	inputsBytes, err := out.Inputs.InputsMarshal()
	require.NoError(t, err)

	var inputsObj jsonObj
	err = json.Unmarshal(inputsBytes, &inputsObj)
	require.NoError(t, err)

	jsonWant, err := os.ReadFile(
		"testdata/atomic_query_sig_v2_merklized_output.json")
	require.NoError(t, err)
	var wantObj jsonObj
	err = json.Unmarshal(jsonWant, &wantObj)
	require.NoError(t, err)
	wantObj["timestamp"] = inputsObj["timestamp"]

	require.Equal(t, wantObj, inputsObj, "got: %s", inputsBytes)

	wantVerifiablePresentation := map[string]any{
		"@context": []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		},
		"@type": "VerifiablePresentation",
		"verifiableCredential": map[string]any{
			"@type":        "KYCAgeCredential",
			"documentType": float64(2),
		},
	}
	require.Equal(t, wantVerifiablePresentation, out.VerifiablePresentation)
}

func TestAtomicQuerySigV2InputsFromJson_NonMerklized(t *testing.T) {
	defer mockHttpClient(t, map[string]string{
		"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
		"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v2.json":                                                       "testdata/httpresp_KYCAgeCredential-v2.json",
	})()

	jsonIn, err := os.ReadFile("testdata/atomic_query_sig_v2_non_merklized_inputs.json")
	require.NoError(t, err)

	ctx := context.Background()
	var emptyCfg EnvConfig
	out, err := AtomicQuerySigV2InputsFromJson(ctx, emptyCfg, jsonIn)
	require.NoError(t, err)

	inputsBytes, err := out.Inputs.InputsMarshal()
	require.NoError(t, err)

	var inputsObj jsonObj
	err = json.Unmarshal(inputsBytes, &inputsObj)
	require.NoError(t, err)

	jsonWant, err := os.ReadFile("testdata/atomic_query_sig_v2_non_merklized_output.json")
	require.NoError(t, err)
	var wantObj jsonObj
	err = json.Unmarshal(jsonWant, &wantObj)
	require.NoError(t, err)
	wantObj["timestamp"] = inputsObj["timestamp"]

	require.Equal(t, wantObj, inputsObj)

	require.Nil(t, out.VerifiablePresentation, "got: %s", inputsBytes)
}

func TestAtomicQuerySigV2InputsFromJson_NonMerklized_Disclosure(t *testing.T) {
	defer mockHttpClient(t, map[string]string{
		"https://www.w3.org/2018/credentials/v1": "testdata/httpresp_credentials_v1.json",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                                  "testdata/httpresp_iden3credential_v2.json",
		"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/3878863870": "testdata/httpresp_rev_status_3878863870.json",
		"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui/claims/revocation/status/0":          "testdata/httpresp_rev_status_2qDNRmjPHUrtnPWfXQ4kKwZfarfsSYoiFBxB9tDkui_0.json",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v2.json":                                                       "testdata/httpresp_KYCAgeCredential-v2.json",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                              "testdata/httpresp_kyc-v3.json-ld",
	})()

	jsonIn, err := os.ReadFile(
		"testdata/atomic_query_sig_v2_non_merklized_disclosure_inputs.json")
	require.NoError(t, err)

	ctx := context.Background()
	var emptyCfg EnvConfig
	out, err := AtomicQuerySigV2InputsFromJson(ctx, emptyCfg, jsonIn)
	require.NoError(t, err)

	inputsBytes, err := out.Inputs.InputsMarshal()
	require.NoError(t, err)

	var inputsObj jsonObj
	err = json.Unmarshal(inputsBytes, &inputsObj)
	require.NoError(t, err)

	jsonWant, err := os.ReadFile("testdata/atomic_query_sig_v2_non_merklized_output.json")
	require.NoError(t, err)
	var wantObj jsonObj
	err = json.Unmarshal(jsonWant, &wantObj)
	require.NoError(t, err)
	wantObj["timestamp"] = inputsObj["timestamp"]

	require.Equal(t, wantObj, inputsObj, "got: %s", inputsBytes)

	wantVerifiablePresentation := map[string]any{
		"@context": []string{
			"https://www.w3.org/2018/credentials/v1",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld",
		},
		"@type": "VerifiablePresentation",
		"verifiableCredential": map[string]any{
			"@type":        "KYCAgeCredential",
			"documentType": float64(99),
		},
	}
	require.Equal(t, wantVerifiablePresentation, out.VerifiablePresentation)
}

func TestEnvConfig__UnmarshalJSON(t *testing.T) {
	in := `{
  "ethereumUrl": "http://localhost:8545",
  "stateContractAddr": "0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655",
  "reverseHashServiceUrl": "http://localhost:8003"
}`
	var out EnvConfig
	err := json.Unmarshal([]byte(in), &out)
	require.NoError(t, err)
	stateContractAddr := common.HexToAddress(
		"0xEA9aF2088B4a9770fC32A12fD42E61BDD317E655")
	require.Equal(t, "http://localhost:8545", out.EthereumURL)
	require.Equal(t, stateContractAddr, out.StateContractAddr)
	require.Equal(t, "http://localhost:8003", out.ReverseHashServiceUrl)
}
