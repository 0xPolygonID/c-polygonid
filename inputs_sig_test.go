package c_polygonid

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/stretchr/testify/require"
)

type mockedRouterTripper struct{}

func (m mockedRouterTripper) RoundTrip(
	request *http.Request) (*http.Response, error) {

	responses := map[string]string{
		"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0": `{
  "issuer": {
    "state": "2b9d4abe9012cc337d3d347b66659cc45091f822dccb004d88d9f1459e2de306",
    "rootOfRoots": "de10563602d76d3ea12bc4d33ecf965dc09151da6139fcdc719bcdb79a20401e",
    "claimsTreeRoot": "ff95462f61fd6c72e16c2ca5a71c55d2456e695f5d50cc05ede2340fd54d651f",
    "revocationTreeRoot": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "mtp": {
    "existence": false,
    "siblings": []
  }
}`,
		"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481": `{
  "issuer": {
    "state": "2b9d4abe9012cc337d3d347b66659cc45091f822dccb004d88d9f1459e2de306",
    "rootOfRoots": "de10563602d76d3ea12bc4d33ecf965dc09151da6139fcdc719bcdb79a20401e",
    "claimsTreeRoot": "ff95462f61fd6c72e16c2ca5a71c55d2456e695f5d50cc05ede2340fd54d651f",
    "revocationTreeRoot": "0000000000000000000000000000000000000000000000000000000000000000"
  },
  "mtp": {
    "existence": false,
    "siblings": []
  }
}`,
	}

	response, ok := responses[request.URL.String()]
	if ok {
		rr := httptest.NewRecorder()
		_, err := rr.WriteString(response)
		if err != nil {
			panic(err)
		}
		return rr.Result(), nil
	} else {
		return http.DefaultTransport.RoundTrip(request)
	}
}

func TestAtomicQuerySigV2InputsFromJson(t *testing.T) {
	oldRoundTripper := httpClient.Transport
	defer func() {
		httpClient.Transport = oldRoundTripper
	}()
	httpClient.Transport = mockedRouterTripper{}

	jsonIn, err := os.ReadFile("testdata/atomic_query_mtp_v2_inputs.json")
	require.NoError(t, err)

	out, err := atomicQuerySigV2InputsFromJson(jsonIn)
	require.NoError(t, err)

	inputsBytes, err := out.InputsMarshal()
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

	require.Equal(t, wantObj, inputsObj)
	//t.Log(string(inputsBytes))
}

func TestHexHash_UnmarshalJSON(t *testing.T) {
	s := `"2b9d4abe9012cc337d3d347b66659cc45091f822dccb004d88d9f1459e2de306"`
	var h hexHash
	err := h.UnmarshalJSON([]byte(s))
	require.NoError(t, err)
}

func TestW3CCredentialUnmarshal(t *testing.T) {
	var y struct {
		VC json.RawMessage `json:"verifiableCredentials"`
	}

	jsonIn, err := os.ReadFile("testdata/atomic_query_mtp_v2_inputs.json")
	require.NoError(t, err)

	err = json.Unmarshal(jsonIn, &y)
	require.NoError(t, err)

	var x verifiable.W3CCredential
	err = json.Unmarshal(y.VC, &x)

	xBytes, err := json.Marshal(x)
	require.NoError(t, err)
	t.Log(string(xBytes))
}
