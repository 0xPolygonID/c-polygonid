package main

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	core "github.com/iden3/go-iden3-core"
	"github.com/stretchr/testify/require"
)

func TestGenerateAuthClaimData(t *testing.T) {
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
