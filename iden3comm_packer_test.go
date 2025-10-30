package c_polygonid

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	httpmock "github.com/0xPolygonID/c-polygonid/testing"
	"github.com/ethereum/go-ethereum/common"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	jweProvider "github.com/iden3/iden3comm/v2/packers/providers/jwe"
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
	require.ErrorIs(t, err, jweProvider.ErrDecryptionKeyNotFound)
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

func TestDecryptJWE(t *testing.T) {
	expectedCredentialJSON := `{"id":"urn:uuid:a6b89dca-a8e8-11f0-9e07-3ec1cb51743a","@context":["https://www.w3.org/2018/credentials/v1","https://schema.iden3.io/core/jsonld/iden3proofs.jsonld","https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"],"type":["VerifiableCredential","KYCAgeCredential"],"expirationDate":"2030-04-25T16:29:26+02:00","issuanceDate":"2025-10-14T10:29:23.35386Z","credentialSubject":{"birthday":19960424,"documentType":2,"id":"did:iden3:polygon:mumbai:x3HstHLj2rTp6HHXk2WczYP7w3rpCsRbwCMeaQ2H2","type":"KYCAgeCredential"},"credentialStatus":{"id":"https://issuernode-mumbai-protocol.polygonid.me/v2/agent","type":"Iden3commRevocationStatusV1.0","revocationNonce":2229961145},"issuer":"did:polygonid:polygon:amoy:2qXnMYUfndFcM4NVVjbCrzjfMj9eoDYw6Y7zXtHaHR","credentialSchema":{"id":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json","type":"JsonSchema2023"}}`

	fp := filepath.Join("testdata", "jwe_decrypt_input.json")
	packInput, err := os.ReadFile(fp)
	require.NoError(t, err)

	plaintext, err := DecryptJWE(packInput)
	require.NoError(t, err)
	require.NotEmpty(t, plaintext)

	var credential verifiable.W3CCredential
	require.NoError(t, json.Unmarshal(plaintext, &credential))

	require.JSONEq(t, expectedCredentialJSON, string(plaintext))
}

func TestDecryptEncryptedCredential_SigProof_Revocation_Type_RHS(t *testing.T) {
	expectedCredentialJSON := `{"id":"urn:uuid:41aa8319-ab6c-11f0-bd47-0a58a9feac02","@context":["https://www.w3.org/2018/credentials/v1","https://schema.iden3.io/core/jsonld/iden3proofs.jsonld","https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"],"type":["VerifiableCredential","KYCAgeCredential"],"expirationDate":"2030-04-25T14:29:26Z","issuanceDate":"2025-10-17T15:16:29.636126436Z","credentialSubject":{"birthday":19960424,"documentType":2,"id":"did:iden3:polygon:amoy:xCyw7Zbuw7Umx43ArACPY5hdHM7AFC6s7hahGE6vX","type":"KYCAgeCredential"},"credentialStatus":{"id":"https://rhs-staging.polygonid.me/node?state=674da9f0e386201c86348b42e2ac34ac885613d3329f1684fc15051dd171892e","type":"Iden3ReverseSparseMerkleTreeProof","revocationNonce":1164257065,"statusIssuer":{"id":"https://issuer-node-core-api-testing.privado.id/v2/agent","type":"Iden3commRevocationStatusV1.0","revocationNonce":1164257065}},"issuer":"did:polygonid:polygon:amoy:2qWBHM4gURfUd6Fc3s1wiEAEWhypWoiPuM3GuJM1op","credentialSchema":{"id":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json","type":"JsonSchema2023"}}`

	fp := filepath.Join("testdata", "jwe_decrypt_input_w3c_credential.json")
	packInput, err := os.ReadFile(fp)
	require.NoError(t, err)

	fn := func(path string) string {
		return fmt.Sprintf("testdata/%s", path)
	}

	defer httpmock.MockHTTPClient(t,
		map[string]string{
			`http://localhost:8545%%%{"jsonrpc":"2.0","method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0xb4bdea55000b272e8971d11d0515fc84169f32d3135688ac34ace2428b34861c20861302","to":"0x134b1be34911e39a8397ec6289782989729807a4"},"latest"]}`:                                                                 fn("httpresp_eth_state_2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X.json"),
			`http://localhost:8545%%%{"jsonrpc":"2.0","method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x110c96a7000e5102b2f7a54e61db03f6c656f65062f4b11b9dd52a1702c2bfdc379d12020000000000000000000000000000000000000000000000000000000026d96d5e","to":"0x49b84b9dd137de488924b18299de8bf46fd11469"},"latest"]}`: fn("httpresp_eth_iden3state_2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X_rev_status_651783518.json"),
			"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld":                                         fn("httpresp_iden3proofs.jsonld"),
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": fn("httpresp_kyc-v3.json-ld"),
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld":  fn("httpresp_kyc_v4.jsonld"),
			"https://resolver.privado.id/1.0/identifiers/did%3Apolygonid%3Apolygon%3Aamoy%3A2qWBHM4gURfUd6Fc3s1wiEAEWhypWoiPuM3GuJM1op?state=674da9f0e386201c86348b42e2ac34ac885613d3329f1684fc15051dd171892e": fn("httpresp_universal_verifier_state_674da9f0e386201c86348b42e2ac34ac885613d3329f1684fc15051dd171892e.json"),
			"https://rhs-staging.polygonid.me/node/5a166f339f23fb53ae7433909eaf7eee27431f4e3ac038c329416e38a48a5818":                                                                                           fn("httpresp_rhs_staging_5a166f339f23fb53ae7433909eaf7eee27431f4e3ac038c329416e38a48a5818.json"),
		},
		httpmock.IgnoreUntouchedURLs(),
		httpmock.WithPostRequestBodyProcessor(removeIdFromEthBody))()
	cfg := EnvConfig{
		ChainConfigs: map[core.ChainID]ChainConfig{
			80002: {
				RPCUrl:            "http://localhost:8545",
				StateContractAddr: common.HexToAddress("0x134B1BE34911E39A8397ec6289782989729807a4"),
			},
		},

		DIDResolverURL: "https://resolver.privado.id/1.0/identifiers",
	}

	plaintext, err := DecryptEncryptedCredential(context.Background(), cfg, packInput)
	require.NoError(t, err)
	require.NotEmpty(t, plaintext)

	require.JSONEq(t, expectedCredentialJSON, string(plaintext))
}

func TestDecryptEncryptedCredential_SigProof_Revocation_Type_Agent(t *testing.T) {
	expectedCredentialJSON := `{"id":"urn:uuid:fb89c6d6-adb2-11f0-b1b5-0a58a9feac02","@context":["https://www.w3.org/2018/credentials/v1","https://schema.iden3.io/core/jsonld/iden3proofs.jsonld","https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"],"type":["VerifiableCredential","KYCAgeCredential"],"expirationDate":"2030-04-25T14:29:26Z","issuanceDate":"2025-10-20T12:47:48.574761893Z","credentialSubject":{"birthday":19960424,"documentType":2,"id":"did:iden3:polygon:amoy:xCyw7Zbuw7Umx43ArACPY5hdHM7AFC6s7hahGE6vX","type":"KYCAgeCredential"},"credentialStatus":{"id":"https://issuer-node-core-api-testing.privado.id/v2/agent","type":"Iden3commRevocationStatusV1.0","revocationNonce":1964841539},"issuer":"did:polygonid:polygon:amoy:2qZpXYbQ9JA7xjxZXXh1WJkc9eaN49XChzCfgYCYMZ","credentialSchema":{"id":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json","type":"JsonSchema2023"}}`
	fp := filepath.Join("testdata", "jwe_decrypt_input_w3c_credential_agent_revocation.json")
	packInput, err := os.ReadFile(fp)
	require.NoError(t, err)

	fn := func(path string) string {
		return fmt.Sprintf("testdata/%s", path)
	}

	mockBodyProcessorFunc := func(url string, body []byte) []byte {
		if url == "https://issuer-node-core-api-testing.privado.id/v2/agent" {
			return []byte{}
		}
		return removeIdFromEthBody(url, body)
	}
	defer httpmock.MockHTTPClient(t,
		map[string]string{
			`http://localhost:8545%%%{"jsonrpc":"2.0","method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0xb4bdea55000b272e8971d11d0515fc84169f32d3135688ac34ace2428b34861c20861302","to":"0x134b1be34911e39a8397ec6289782989729807a4"},"latest"]}`:                                                                 fn("httpresp_eth_state_2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X.json"),
			`http://localhost:8545%%%{"jsonrpc":"2.0","method":"eth_call","params":[{"from":"0x0000000000000000000000000000000000000000","input":"0x110c96a7000e5102b2f7a54e61db03f6c656f65062f4b11b9dd52a1702c2bfdc379d12020000000000000000000000000000000000000000000000000000000026d96d5e","to":"0x49b84b9dd137de488924b18299de8bf46fd11469"},"latest"]}`: fn("httpresp_eth_iden3state_2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X_rev_status_651783518.json"),
			"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld":                                         fn("httpresp_iden3proofs.jsonld"),
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": fn("httpresp_kyc-v3.json-ld"),
			"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v4.jsonld":  fn("httpresp_kyc_v4.jsonld"),
			"https://resolver.privado.id/1.0/identifiers/did%3Apolygonid%3Apolygon%3Aamoy%3A2qZpXYbQ9JA7xjxZXXh1WJkc9eaN49XChzCfgYCYMZ?state=e8f0256542d65ab4dd5fe2b4959075b1c54a810a644f2f950018866c25d70411": fn("httpresp_universal_verifier_state_e8f0256542d65ab4dd5fe2b4959075b1c54a810a644f2f950018866c25d70411.json"),
			"https://issuer-node-core-api-testing.privado.id/v2/agent%%%": fn("httpresp_agent_revocation_to_did:polygonid:polygon:amoy:2qZpXYbQ9JA7xjxZXXh1WJkc9eaN49XChzCfgYCYMZ.json"),
		},
		httpmock.IgnoreUntouchedURLs(),
		httpmock.WithPostRequestBodyProcessor(mockBodyProcessorFunc),
	)()
	cfg := EnvConfig{
		ChainConfigs: map[core.ChainID]ChainConfig{
			80002: {
				RPCUrl:            "http://localhost:8545",
				StateContractAddr: common.HexToAddress("0x134B1BE34911E39A8397ec6289782989729807a4"),
			},
		},

		DIDResolverURL: "https://resolver.privado.id/1.0/identifiers",
	}

	plaintext, err := DecryptEncryptedCredential(context.Background(), cfg, packInput)
	require.NoError(t, err)
	require.NotEmpty(t, plaintext)

	require.JSONEq(t, expectedCredentialJSON, string(plaintext))
}
