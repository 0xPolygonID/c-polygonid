package c_polygonid

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBabyJubJubSignPoseidon(t *testing.T) {
	testCases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{
			in: `{
  "private_key": "b8284dcade2f26c5ddd3b6ac5c1d728ecae9b23250bb5d35d40a3dd33f048e"
}`,
			wantErr: `failed to unmarshal request: invalid private key length`,
		},
		{
			in: `{
  "private_key": "b8284dcade2f26c5ddd3b6ac524c1d728ecae9b23250bb5d35d40a3dd33f048e"
}`,
			wantErr: `message is not set`,
		},
		{
			in: `{
  "private_key": "b8284dcade2f26c5ddd3b6ac524c1d728ecae9b23250bb5d35d40a3dd33f048e",
  "msg_int": "100500"
}`,
			want: `{
  "signature": "c69e5ca2806d17158b35f29ff8f92b8cc00930d124261c4180573ce07ec80f0ad2f68a3073d56a0fab81a581a1b5f4925a504a019db3779a0fc398ee37059b05"
}`,
		},
		{
			in:      `{}`,
			wantErr: `private key is not set`,
		},
	}

	for idx, tc := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			ctx := context.Background()
			resp, err := BabyJubJubSignPoseidon(ctx, EnvConfig{}, []byte(tc.in))
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Equal(t, tc.wantErr, err.Error())
			} else {
				require.NoError(t, err)
				respJson, err := json.Marshal(resp)
				require.NoError(t, err)
				require.JSONEq(t, tc.want, string(respJson))
			}
		})
	}
}

func TestBabyJubJubVerifyPoseidon(t *testing.T) {
	testCases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{
			in: `{
  "public_key": "b6d7e677e96eae743551a4db2f9d78e7e974a65e5965dce933c17e1bc81380a2",
  "msg_int": "100500"
}`,
			wantErr: `signature is not set`,
		},
		{
			in: `{
  "public_key": "b6d7e677e96eae743551a4db2f9d78e7e974a65e5965dce933c17e1bc81380a2",
  "msg_int": "100500",
  "signature": "c69e5ca2806d17158b35f29ff8f92b8cc00930d124261c4180573ce07ec80f0ad2f68a3073d56a0fab81a581a1b5f4925a504a019db3779a0fc398ee37059b05"
}`,
			want: `{"valid": true}`,
		},
		{
			in: `{
  "public_key": "b6d7e677e96eae743551a4db2f9d78e7e974a65e5965dce933c17e1bc81380a2",
  "msg_int": "100501",
  "signature": "c69e5ca2806d17158b35f29ff8f92b8cc00930d124261c4180573ce07ec80f0ad2f68a3073d56a0fab81a581a1b5f4925a504a019db3779a0fc398ee37059b05"
}`,
			want: `{"valid": false}`,
		},
	}

	for idx, tc := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			ctx := context.Background()
			resp, err := BabyJubJubVerifyPoseidon(ctx, EnvConfig{}, []byte(tc.in))
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Equal(t, tc.wantErr, err.Error())
			} else {
				require.NoError(t, err)
				respJson, err := json.Marshal(resp)
				require.NoError(t, err)
				require.JSONEq(t, tc.want, string(respJson))
			}
		})
	}
}

func TestBabyJubJubPrivate2Public(t *testing.T) {
	testCases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{
			in: `{
  "private_key": "b8284dcade2f26c5ddd3b6ac524c1d728ecae9b23250bb5d35d40a3dd33f048e"
}`,
			want: `{
  "public_key": "b6d7e677e96eae743551a4db2f9d78e7e974a65e5965dce933c17e1bc81380a2",
  "public_key_x_int": "21241797485017627462131959691037462653200294188088281099570857109629667091940",
  "public_key_y_int": "15604929804188188583235249350576701257034402006903904828344484717210494228406"
}`,
		},
		{
			in: `{
  "private_key2": "b8284dcade2f26c5ddd3b6ac524c1d728ecae9b23250bb5d35d40a3dd33f048e"
}`,
			wantErr: `private key is not set`,
		},
	}

	for idx, tc := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			ctx := context.Background()
			resp, err := BabyJubJubPrivate2Public(ctx, EnvConfig{},
				[]byte(tc.in))
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Equal(t, tc.wantErr, err.Error())
			} else {
				require.NoError(t, err)
				respJson, err := json.Marshal(resp)
				require.NoError(t, err)
				require.JSONEq(t, tc.want, string(respJson))
			}
		})
	}
}

func TestBabyJubJubPublicUncompress(t *testing.T) {
	testCases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{
			in: `{
  "public_key": "b6d7e677e96eae743551a4db2f9d78e7e974a65e5965dce933c17e1bc81380a2"
}`,
			want: `{
  "public_key_x_int": "21241797485017627462131959691037462653200294188088281099570857109629667091940",
  "public_key_y_int": "15604929804188188583235249350576701257034402006903904828344484717210494228406"
}`,
		},
		{
			in: `{
  "private_key2": "b8284dcade2f26c5ddd3b6ac524c1d728ecae9b23250bb5d35d40a3dd33f048e"
}`,
			wantErr: `public key is not set`,
		},
	}

	for idx, tc := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			ctx := context.Background()
			resp, err := BabyJubJubPublicUncompress(ctx, EnvConfig{},
				[]byte(tc.in))
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Equal(t, tc.wantErr, err.Error())
			} else {
				require.NoError(t, err)
				respJson, err := json.Marshal(resp)
				require.NoError(t, err)
				require.JSONEq(t, tc.want, string(respJson))
			}
		})
	}
}

func TestBabyJubJubPublicCompress(t *testing.T) {
	testCases := []struct {
		in      string
		want    string
		wantErr string
	}{
		{
			in: `{
  "public_key_x_int": "21241797485017627462131959691037462653200294188088281099570857109629667091940",
  "public_key_y_int": "15604929804188188583235249350576701257034402006903904828344484717210494228406"
}`,
			want: `{
  "public_key": "b6d7e677e96eae743551a4db2f9d78e7e974a65e5965dce933c17e1bc81380a2"
}`,
		},
		{
			in: `{
  "private_key2": "b8284dcade2f26c5ddd3b6ac524c1d728ecae9b23250bb5d35d40a3dd33f048e"
}`,
			wantErr: `public key X is not set`,
		},
	}

	for idx, tc := range testCases {
		t.Run(strconv.Itoa(idx), func(t *testing.T) {
			ctx := context.Background()
			resp, err := BabyJubJubPublicCompress(ctx, EnvConfig{},
				[]byte(tc.in))
			if tc.wantErr != "" {
				require.Error(t, err)
				require.Equal(t, tc.wantErr, err.Error())
			} else {
				require.NoError(t, err)
				respJson, err := json.Marshal(resp)
				require.NoError(t, err)
				require.JSONEq(t, tc.want, string(respJson))
			}
		})
	}
}
