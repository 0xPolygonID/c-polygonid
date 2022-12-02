package c_polygonid

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func sToI(in string) *big.Int {
	i, ok := new(big.Int).SetString(in, 10)
	if !ok {
		panic(in)
	}
	return i
}

func TestSmartContractProof_UnmarshalJSON(t *testing.T) {
	in := []byte(`{
 "Root": "17039823904837071705763545555283546217751326723169195059364451777353741017328",
  "Siblings": [
    "14989532119404983961115670288381063073891118401716735992353404523801340288158",
    "15817549995119513546413395894800310537308858548528902759332598606866792105384",
    "20955911300871905860419417343337237575819647673394656670247178513070221579793",
    "7345857457589225232320640926291449425076936633178262764678572453063445218154",
    "13941064550735375985967548290421702932981128763694428458881182266843384273940",
    "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0",
    "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"
  ],
  "OldKey": "10",
  "OldValue": "20",
  "IsOld0": true,
  "Key": "13625694351531357880063798347796487002182037278253017013343168668336623401886",
  "Value": "0",
  "Fnc": "1"
}`)
	want := SmartContractProof{
		Root: sToI("17039823904837071705763545555283546217751326723169195059364451777353741017328"),
		Siblings: []*big.Int{
			sToI("14989532119404983961115670288381063073891118401716735992353404523801340288158"),
			sToI("15817549995119513546413395894800310537308858548528902759332598606866792105384"),
			sToI("20955911300871905860419417343337237575819647673394656670247178513070221579793"),
			sToI("7345857457589225232320640926291449425076936633178262764678572453063445218154"),
			sToI("13941064550735375985967548290421702932981128763694428458881182266843384273940"),
			big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
			big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
			big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
			big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
			big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
			big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0),
			big.NewInt(0), big.NewInt(0), big.NewInt(0),
		},
		OldKey:   big.NewInt(10),
		OldValue: big.NewInt(20),
		IsOld0:   true,
		Fnc:      big.NewInt(1),
	}

	var res SmartContractProof
	err := res.UnmarshalJSON(in)
	require.NoError(t, err)
	require.Equal(t, want, res)
}
