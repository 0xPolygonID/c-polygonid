package c_polygonid

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJsonNumber_UnmarshalJSON(t *testing.T) {
	in := `123`
	var jn = new(big.Int)
	err := ((*jsonNumber)(jn)).UnmarshalJSON([]byte(in))
	require.NoError(t, err)
	require.Equal(t, "123", jn.String())

	var jn2 struct {
		Jn *jsonNumber
	}
	in2 := `{"jn":123}`
	err = json.Unmarshal([]byte(in2), &jn2)
	require.NoError(t, err)
	require.Equal(t, "123", ((*big.Int)(jn2.Jn)).String())

	var jn3 struct {
		Jn *jsonNumber
	}
	in3 := `{"jn":"123"}`
	err = json.Unmarshal([]byte(in3), &jn3)
	require.NoError(t, err)
	require.Equal(t, "123", ((*big.Int)(jn3.Jn)).String())

	var jn4 struct {
		Jn *jsonNumber
	}
	in4 := `{"jn":"0x123"}`
	err = json.Unmarshal([]byte(in4), &jn4)
	require.NoError(t, err)
	require.Equal(t, "291", ((*big.Int)(jn4.Jn)).String())

	var jn5 struct {
		Jn *jsonNumber
	}
	in5 := `{"jn":"0X123"}`
	err = json.Unmarshal([]byte(in5), &jn5)
	require.NoError(t, err)
	require.Equal(t, "291", ((*big.Int)(jn5.Jn)).String())

	in6 := `123.4`
	var jn6 = new(big.Int)
	err = json.Unmarshal([]byte(in6), (*jsonNumber)(jn6))
	require.EqualError(t, err, "invalid integer number format")

	var jn7 = new(big.Int)
	err = ((*jsonNumber)(jn7)).UnmarshalJSON(nil)
	require.EqualError(t, err, "empty input")
}

func TestJsonByte_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		in   []byte
		want byte
		err  string
	}{
		{[]byte(`123`), 123, ""},
		{[]byte(`"123"`), 123, ""},
		{[]byte(`"0xab"`), 171, ""},
		{[]byte(`"0xa"`), 10, ""},
		{[]byte(`"0xabc"`), 172,
			"strconv.ParseUint: parsing \"abc\": value out of range"},
		{[]byte(`"0B101011"`), 43, ""},
	}

	for _, tc := range testCases {
		t.Run(string(tc.in), func(t *testing.T) {
			var jb jsonByte
			err := json.Unmarshal(tc.in, &jb)
			if tc.err != "" {
				require.EqualError(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, jsonByte(tc.want), jb)
		})
	}
}
