package main

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"math/rand"
	"strings"
	"testing"
	"time"

	core "github.com/iden3/go-iden3-core"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/stretchr/testify/require"
)

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
	id, err := core.IdGenesisFromIdenState(core.TypeDefault, state)
	require.NoError(t, err)
	t.Log(id)
}

func intFromStr(iStr string) *big.Int {
	i, ok := new(big.Int).SetString(iStr, 10)
	if !ok {
		panic("invalid int")
	}
	return i
}

func idFromStr(iStr string) core.ID {
	id, err := core.IDFromString(iStr)
	if err != nil {
		panic("invalid id")
	}
	return id
}

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
