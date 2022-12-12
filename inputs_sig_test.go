package c_polygonid

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"text/template"

	"github.com/stretchr/testify/require"
)

func TestAtomicQuerySigV2InputsFromJson(t *testing.T) {
	router := http.NewServeMux()
	router.HandleFunc("/api/v1/identities/did:iden3:polygon:mumbai:wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/2376431481",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{
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
}`)
		})
	router.HandleFunc("/api/v1/identities/did:iden3:polygon:mumbai:wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0",
		func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{
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
}`)
		})
	ts := httptest.NewServer(router)
	defer ts.Close()

	//jsonBytes, err := os.ReadFile("testdata/atomic_query_mtp_v2_inputs.go")
	//jsonBytes, err := os.ReadFile("/Users/alek/src/go-circuits/testdata/atomic_query_mtp_v2_inputs.json")
	//require.NoError(t, err)

	tmpl, err := template.ParseFiles("/Users/alek/src/go-circuits/testdata/atomic_query_mtp_v2_inputs.json")
	require.NoError(t, err)
	var buf bytes.Buffer
	err = tmpl.Execute(&buf, struct{ MockServer string }{MockServer: ts.URL})
	require.NoError(t, err)

	//t.Log(buf.String())

	out, err := atomicQuerySigV2InputsFromJson(buf.Bytes())
	require.NoError(t, err)

	inputsBytes, err := out.InputsMarshal()
	require.NoError(t, err)

	t.Log(string(inputsBytes))
}

func TestHexHash_UnmarshalJSON(t *testing.T) {
	s := `"2b9d4abe9012cc337d3d347b66659cc45091f822dccb004d88d9f1459e2de306"`
	var h hexHash
	err := h.UnmarshalJSON([]byte(s))
	require.NoError(t, err)
}
