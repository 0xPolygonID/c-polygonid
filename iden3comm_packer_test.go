package c_polygonid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/stretchr/testify/require"
)

func compareWithSourceMessage(t *testing.T, source, actual []byte) {
	type message struct {
		Message json.RawMessage `json:"message"`
	}
	expect := &message{}
	err := json.Unmarshal(source, expect)
	require.NoError(t, err)

	require.JSONEq(t, string(expect.Message), string(actual))
}

func TestAnonPackFlow_RSA(t *testing.T) {
	fp := filepath.Join("testdata", "anon_pack_inputs.json")
	packInput, err := os.ReadFile(fp)
	require.NoError(t, err)

	ciphertext, err := AnonPack(packInput)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	recipients := []string{
		filepath.Join("testdata", "keys", "alice_private_key_rsa_set_only.json"),
		filepath.Join("testdata", "keys", "bob_private_key_rsa_set_only.json"),
		filepath.Join("testdata", "keys", "viktor_private_key_rsa_set_only.json"),
	}

	for _, r := range recipients {
		t.Run(r, func(t *testing.T) {
			keysetBytes, err := os.ReadFile(r)
			require.NoError(t, err)

			unpackInput, err := json.Marshal(anonUnpackerInput{
				Ciphertext: ciphertext,
				KeySet:     keysetBytes,
			})
			require.NoError(t, err)

			plaintext, err := AnonUnpack(unpackInput)
			require.NoError(t, err)
			require.NotEmpty(t, plaintext)

			compareWithSourceMessage(t, packInput, plaintext)
		})
	}
}

func TestAnonPackFlow_Multi(t *testing.T) {
	fp := filepath.Join("testdata", "anon_pack_inputs_multi.json")
	packInput, err := os.ReadFile(fp)
	require.NoError(t, err)

	ciphertext, err := AnonPack(packInput)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	recipients := []string{
		filepath.Join("testdata", "keys", "alice_private_key_rsa_set_only.json"),
		filepath.Join("testdata", "keys", "bob_private_key_ec_set_only.json"),
		filepath.Join("testdata", "keys", "viktor_private_key_rsa_set_only.json"),
	}

	for _, r := range recipients {
		t.Run(r, func(t *testing.T) {
			keysetBytes, err := os.ReadFile(r)
			require.NoError(t, err)

			unpackInput, err := json.Marshal(anonUnpackerInput{
				Ciphertext: ciphertext,
				KeySet:     keysetBytes,
			})
			require.NoError(t, err)

			plaintext, err := AnonUnpack(unpackInput)
			require.NoError(t, err)
			require.NotEmpty(t, plaintext)

			compareWithSourceMessage(t, packInput, plaintext)
		})
	}
}

func TestAnonPack_Error_MultipleKeysInSet(t *testing.T) {
	fp := filepath.Join("testdata", "anon_pack_inputs.json")
	packInput, err := os.ReadFile(fp)
	require.NoError(t, err)

	ciphertext, err := AnonPack(packInput)
	require.NoError(t, err)
	require.NotEmpty(t, ciphertext)

	recipients := []string{
		filepath.Join("testdata", "keys", "alice_private_key_rsa_set_only.json"),
		filepath.Join("testdata", "keys", "alice_private_key_ec_set_only.json"),
	}

	mergedKeySet := jwk.NewSet()
	for _, r := range recipients {
		keysetBytes, err := os.ReadFile(r)
		require.NoError(t, err)

		keyset, err := jwk.Parse(keysetBytes)
		require.NoError(t, err)

		k, ok := keyset.Key(0)
		require.True(t, ok)
		require.NotNil(t, k)

		err = mergedKeySet.AddKey(k)
		require.NoError(t, err)
	}

	setBytes, err := json.Marshal(mergedKeySet)
	require.NoError(t, err)

	unpackInput, err := json.Marshal(anonUnpackerInput{
		Ciphertext: ciphertext,
		KeySet:     setBytes,
	})
	require.NoError(t, err)

	_, err = AnonUnpack(unpackInput)
	require.ErrorContains(t, err, "no recipient found")
}

func Benchmark_3_RSA_Recipients(b *testing.B) {
	fp := filepath.Join("testdata", "anon_pack_inputs.json")
	packInput, err := os.ReadFile(fp)
	require.NoError(b, err)

	var finalCiphertexts []byte
	b.Run("Pack", func(b *testing.B) {
		for b.Loop() {
			finalCiphertexts, err = AnonPack(packInput)
			require.NoError(b, err)
			require.NotEmpty(b, finalCiphertexts)
		}
	})

	b.Run("Unpack_Alice_Only", func(b *testing.B) {
		var keysetBytes []byte
		keysetBytes, err = os.ReadFile(
			filepath.Join("testdata", "keys", "alice_private_key_rsa_set_only.json"))
		require.NoError(b, err)

		var unpackInput []byte
		unpackInput, err = json.Marshal(anonUnpackerInput{
			Ciphertext: finalCiphertexts,
			KeySet:     keysetBytes,
		})
		require.NoError(b, err)

		for b.Loop() {
			finalPlaintext, err := AnonUnpack(unpackInput)
			require.NoError(b, err)
			require.NotEmpty(b, finalPlaintext)
		}
	})
}
