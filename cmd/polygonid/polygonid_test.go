package main

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"log/slog"
	"math/big"
	"math/rand"
	"os"
	"strings"
	"testing"
	"time"

	c_polygonid "github.com/0xPolygonID/c-polygonid"
	httpmock "github.com/0xPolygonID/c-polygonid/testing"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"
)

var catchUnusedHttpresp = flag.Bool("find-unused-httpresp", false,
	"fail if there are unused httpresp_* files")

func TestMain(m *testing.M) {
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		AddSource:   true,
		Level:       slog.LevelInfo,
		ReplaceAttr: nil,
	})))

	retCode := m.Run()
	flag.Parse()

	if *catchUnusedHttpresp {
		if !httpmock.CheckForRedundantHttpresps("testdata", "httpresp_") {
			os.Exit(1)
		}
	}

	os.Exit(retCode)
}

func TestGenerateAuthClaimData(t *testing.T) {
	t.Skip("generate auth claim data")
	var schema core.SchemaHash
	n, err := hex.NewDecoder(
		strings.NewReader("ca938857241db9451ea329256b9c06e5")).
		Read(schema[:])
	require.NoError(t, err)
	require.Equal(t, len(schema), n)

	nonce := uint64(13260572831089785859)

	keyX, ok := new(big.Int).SetString(
		"15468939102716291673743744296736132867654217747684906302563904432835075522918",
		10)
	require.True(t, ok)
	keyY, ok := new(big.Int).SetString(
		"10564057289999407626309237453457578977834988122411075958351091519856342060014",
		10)
	require.True(t, ok)

	c, err := core.NewClaim(schema, core.WithRevocationNonce(nonce),
		core.WithIndexDataInts(keyX, keyY))
	require.NoError(t, err)

	cBytes, err := json.Marshal(c)
	require.NoError(t, err)

	t.Log(string(cBytes))
}

func TestRndID(t *testing.T) {
	t.Skip("generate random id")
	state, err := poseidon.Hash([]*big.Int{big.NewInt(rand.Int63())})
	require.NoError(t, err)
	id, err := core.NewIDFromIdenState(core.TypeDefault, state)
	require.NoError(t, err)
	t.Log(id)
}

//nolint:unused // reason: used in skipped tests
func intFromStr(iStr string) *big.Int {
	i, ok := new(big.Int).SetString(iStr, 10)
	if !ok {
		panic("invalid int")
	}
	return i
}

//nolint:unused // reason: used in skipped tests
func idFromStr(iStr string) core.ID {
	id, err := core.IDFromString(iStr)
	if err != nil {
		panic("invalid id")
	}
	return id
}

//nolint:unused // reason: used in skipped tests
func schemaFromStr(sStr string) core.SchemaHash {
	var schema core.SchemaHash
	n, err := hex.NewDecoder(
		strings.NewReader(sStr)).
		Read(schema[:])
	if err != nil {
		panic(err)
	}
	if n != len(schema) {
		panic("invalid schema")
	}
	return schema
}

// All fields, ID is in the Index, Merkle tree root is in the Index.
func TestCreateClaimAllFields1(t *testing.T) {
	t.Skip("generate claim with all fields for testing")
	c, err := core.NewClaim(schemaFromStr("ca938857241db9451ea329256b9c06e5"),
		core.WithFlagUpdatable(true),
		core.WithVersion(2596996162),
		core.WithIndexMerklizedRoot(intFromStr("7996401410663625921789776067787462356243972550909005153218670594243745209842")),
		core.WithIndexID(idFromStr("1121GYj7CQZt4uGgEXPtZrK13b5LCpGYrogtaFfcwr")),
		core.WithRevocationNonce(13260572831089785859),
		core.WithExpirationDate(time.Date(2022, 4, 5, 6, 7, 8, 0, time.UTC)),
		core.WithValueDataInts(
			intFromStr("18024561811538979000643878677730421068952645099812951960418372110563501175860"),
			intFromStr("14863753991498882527160607919182815367919569904584710955404275924093442727019")))
	require.NoError(t, err)

	cBytes, err := json.Marshal(c)
	require.NoError(t, err)

	t.Log(string(cBytes))
}

// All fields, ID is in the Value, Merkle tree root is in the Value.
func TestCreateClaimAllFields2(t *testing.T) {
	t.Skip("generate claim with all fields for testing")
	c, err := core.NewClaim(schemaFromStr("ca938857241db9451ea329256b9c06e5"),
		core.WithFlagUpdatable(true),
		core.WithVersion(2596996162),
		core.WithValueMerklizedRoot(intFromStr("7996401410663625921789776067787462356243972550909005153218670594243745209842")),
		core.WithValueID(idFromStr("1121GYj7CQZt4uGgEXPtZrK13b5LCpGYrogtaFfcwr")),
		core.WithRevocationNonce(13260572831089785859),
		core.WithExpirationDate(time.Date(2022, 4, 5, 6, 7, 8, 0, time.UTC)),
		core.WithIndexDataInts(
			intFromStr("15468939102716291673743744296736132867654217747684906302563904432835075522918"),
			intFromStr("10564057289999407626309237453457578977834988122411075958351091519856342060014")))
	require.NoError(t, err)

	cBytes, err := json.Marshal(c)
	require.NoError(t, err)

	t.Log(string(cBytes))
}

func readFixtureFile(name string) []byte {
	fileBytes, err := os.ReadFile("testdata/" + name)
	if err != nil {
		panic(err)
	}
	return fileBytes
}

func TestGenerateInputs(t *testing.T) {
	type PrepareInputsFn func(
		ctx context.Context, cfg c_polygonid.EnvConfig, in []byte) (
		c_polygonid.AtomicQueryInputsResponse, error)

	cacheDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	t.Cleanup(func() {
		err := os.RemoveAll(cacheDir)
		require.NoError(t, err)
	})

	doTest := func(t testing.TB, inFile, wantOutFile string,
		fn PrepareInputsFn, wantVR map[string]any, cfg c_polygonid.EnvConfig,
		wantErr string) {

		err := c_polygonid.CleanCache(cacheDir)
		require.NoError(t, err)

		ctx := context.Background()
		out, err := fn(ctx, cfg, readFixtureFile(inFile))
		if wantErr != "" {
			require.EqualError(t, err, wantErr)
			return
		}
		require.NoError(t, err)

		resp, err := marshalInputsResponse(out)
		require.NoError(t, err)

		assertEqualWithoutTimestamp(t, wantOutFile, resp)
	}

	env := c_polygonid.EnvConfig{CacheDir: cacheDir}
	t.Run("atomic_query_v3_on_chain_mtp_inputs", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/3972757": "../../testdata/httpresp_rev_status_3972757.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                           "../../testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                               "../../testdata/httpresp_iden3credential_v2.json",
		})()

		doTest(t, "atomic_query_v3_on_chain_mtp_inputs.json",
			"atomic_query_v3_on_chain_mtp_output.json",
			c_polygonid.AtomicQueryV3OnChainInputsFromJson, nil, env, "")
	})

t.Run("atomic_query_v3_on_chain_stable_mtp_inputs", func(t *testing.T) {
		defer httpmock.MockHTTPClient(t, map[string]string{
			"http://localhost:8001/api/v1/identities/did%3Apolygonid%3Apolygon%3Amumbai%3A2qDnyCaxj4zdYmj6LbegYMjWSnkbKAyqtq31YeuyZV/claims/revocation/status/3972757": "../../testdata/httpresp_rev_status_3972757.json",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld":                                                           "../../testdata/httpresp_kyc-v3.json-ld",
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/iden3credential-v2.json-ld":                                               "../../testdata/httpresp_iden3credential_v2.json",
		})()

		doTest(t, "atomic_query_v3_on_chain_stable_mtp_inputs.json",
			"atomic_query_v3_on_chain_stable_mtp_output.json",
			c_polygonid.GenericInputsFromJson, nil, env, "")
	})

	t.Run("auth_v2_inputs", func(t *testing.T) {
		doTest(t, "auth_v2_inputs_in.json", "auth_v2_inputs_out.json",
			c_polygonid.GenericInputsFromJson, nil, env, "")
	})

	t.Run("auth_v3_inputs", func(t *testing.T) {
		doTest(t, "auth_v3_inputs_in.json", "auth_v3_8_32_inputs_out.json",
			c_polygonid.GenericInputsFromJson, nil, env, "")
	})

	t.Run("auth_v3_8_32_inputs", func(t *testing.T) {
		doTest(t, "auth_v3_8_32_inputs_in.json", "auth_v3_8_32_inputs_out.json",
			c_polygonid.GenericInputsFromJson, nil, env, "")
	})

	t.Run("auth_v2_incorrect_signature_inputs", func(t *testing.T) {
		doTest(t, "auth_v2_incorrect_sig_inputs_in.json", "",
			c_polygonid.GenericInputsFromJson, nil, env, "invalid signature")
	})
}

func assertEqualWithoutTimestamp(t testing.TB, wantFName string,
	actual string) {

	jsonWant := readFixtureFile(wantFName)
	var wantObj map[string]any
	err := json.Unmarshal(jsonWant, &wantObj)
	require.NoError(t, err)

	var actualObj map[string]any
	err = json.Unmarshal([]byte(actual), &actualObj)
	require.NoError(t, err)

	actualInputsObj, ok := actualObj["inputs"].(map[string]any)
	require.True(t, ok)

	if ts, ok := actualInputsObj["timestamp"]; ok {
		wantObj["inputs"].(map[string]any)["timestamp"] = ts
	}

	require.Equal(t, wantObj, actualObj, "file name: %s\nwant: %s\ngot: %s",
		wantFName, jsonWant, actual)
}
