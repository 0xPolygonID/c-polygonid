package c_polygonid

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	httpmock "github.com/0xPolygonID/c-polygonid/testing"
	"github.com/stretchr/testify/require"
)

func readJsonFile(t testing.TB, filename string) []byte {
	jsonIn, err := os.ReadFile("testdata/" + filename)
	require.NoError(t, err)
	return jsonIn
}

func TestCredentialStatusCheck(t *testing.T) {
	defer httpmock.MockHTTPClient(t, map[string]string{
		"http://localhost:8001/api/v1/identities/did%3Aiden3%3Apolygon%3Amumbai%3AwuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU/claims/revocation/status/0": "testdata/httpresp_rev_status_wuQT8NtFq736wsJahUuZpbA8otTzjKGyKj4i4yWtU_0.json",
	}, httpmock.IgnoreUntouchedURLs())()

	jsonIn := readJsonFile(t, "credential_status_request.json")

	ctx := context.Background()
	resp, err := CredentialStatusCheck(ctx, EnvConfig{}, jsonIn)
	require.NoError(t, err)

	respJ, err := json.Marshal(resp)
	require.NoError(t, err)

	require.JSONEq(t, `{"valid": true}`, string(respJ))
}
