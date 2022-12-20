package c_polygonid

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestJsonBigInt_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		in      []byte
		wantErr bool
		want    *big.Int
	}{
		{
			name: "test",
			in:   []byte(`"123"`),
			want: big.NewInt(123),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			j := new(JsonBigInt)
			require.NoError(t, j.UnmarshalJSON(tt.in))
			require.Equal(t, 0, j.BigInt().Cmp(tt.want))
		})
	}
}
