package c_polygonid

import (
	"context"
	"encoding/json"
	"os"
	"testing"

	httpmock "github.com/0xPolygonID/c-polygonid/testing"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/stretchr/testify/require"
)

func makeW3CCred(jsonDoc string) verifiable.W3CCredential {
	var w3cCred verifiable.W3CCredential
	err := json.Unmarshal([]byte(jsonDoc), &w3cCred)
	if err != nil {
		panic(err)
	}

	return w3cCred
}

var w3cCredDoc = `{"id":"https://dd25-62-87-103-47.ngrok-free.app/api/v1/identities/did:polygonid:polygon:mumbai:2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X/claims/f4263c2a-53ae-11ee-a53c-3ec1cb517438","@context":["https://www.w3.org/2018/credentials/v1","https://schema.iden3.io/core/jsonld/iden3proofs.jsonld","https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld"],"type":["VerifiableCredential","KYCAgeCredential"],"expirationDate":"2361-03-21T21:14:48+02:00","issuanceDate":"2023-09-15T13:02:18.062527+03:00","credentialSubject":{"birthday":19960424,"documentType":2,"id":"did:polygonid:polygon:mumbai:2qFgtCjKV3cDjWJapSLMZGfzw7CrodjCcQzLQABByv","type":"KYCAgeCredential"},"credentialStatus":{"id":"did:polygonid:polygon:mumbai:2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X/credentialStatus?revocationNonce=651783518\u0026contractAddress=80001:0x49b84b9Dd137de488924b18299De8bf46fD11469","revocationNonce":651783518,"type":"Iden3OnchainSparseMerkleTreeProof2023"},"issuer":"did:polygonid:polygon:mumbai:2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X","credentialSchema":{"id":"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json/KYCAgeCredential-v3.json","type":"JsonSchema2023"},"proof":[{"type":"Iden3SparseMerkleTreeProof","issuerData":{"id":"did:polygonid:polygon:mumbai:2qKc2ns18nV6uDSfaR1RVd7zF1Nm9vfeNZuvuEXQ3X","state":{"txId":"0x824d08f68e6c5f8ed2fd1e1a7719c3027e5474c27524f33656796056b360237b","blockTimestamp":1694772169,"blockNumber":40137103,"rootOfRoots":"f3b209de35e59081d119334c9aba3b87474f28971b61dca7aeadff5a14e64524","claimsTreeRoot":"5bf08eb140df36ca00d1ca24eb2dd0f1b4b117e92904279020c8bf51e590f920","revocationTreeRoot":"0000000000000000000000000000000000000000000000000000000000000000","value":"5a166f339f23fb53ae7433909eaf7eee27431f4e3ac038c329416e38a48a5818"}},"coreClaim":"c9b2370371b7fa8b3dab2a5ba81b68382a000000000000000000000000000000021246f30c37a622bfbba26de552d3c9d71d189a58d8c7520c24feaf0b8b0d00b914ea81a5d3a7c2655cc5cc79787cf9b2c10a24cd236fa627252b06b2e7ca1b00000000000000000000000000000000000000000000000000000000000000005e6dd92600000000281cdcdf0200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000","mtp":{"existence":true,"siblings":["10474921236147713942078552079582531417664737388924733946611980668334294816825"]}}]}`

func TestInMemoryStorage_MarshalBinary(t *testing.T) {
	mockBadgerLog(t)

	cacheDir, err := os.MkdirTemp("", "")
	require.NoError(t, err)
	t.Cleanup(func() {
		err = os.RemoveAll(cacheDir)
		require.NoError(t, err)
	})

	cfg := EnvConfig{CacheDir: cacheDir}

	defer httpmock.MockHTTPClient(t, map[string]string{
		"https://schema.iden3.io/core/jsonld/iden3proofs.jsonld":                                         "testdata/httpresp_iden3proofs.jsonld",
		"https://raw.githubusercontent.com/iden3/claim-schema-vocab/main/schemas/json-ld/kyc-v3.json-ld": "testdata/httpresp_kyc-v3.json-ld",
	})()

	w3cCred := makeW3CCred(w3cCredDoc)
	mtStorage := newInMemoryStorage()
	ctx := context.Background()
	var mt *merkletree.MerkleTree
	mt, err = merkletree.NewMerkleTree(ctx, mtStorage, mtLevels)
	if err != nil {
		return
	}

	_, err = w3cCred.Merklize(ctx,
		merklize.WithMerkleTree(merklize.MerkleTreeSQLAdapter(mt)),
		merklize.WithDocumentLoader(cfg.documentLoader()))
	require.NoError(t, err)

	storageBytes, err := mtStorage.MarshalBinary()
	require.NoError(t, err)

	mtStorage2 := newInMemoryStorage()
	err = mtStorage2.UnmarshalBinary(storageBytes)
	require.NoError(t, err)

	// implicitly populate hidden Node.key field
	for k, n := range mtStorage2.kv {
		_, err := n.Key()
		require.NoError(t, err)
		mtStorage2.kv[k] = n
	}

	require.Equal(t, mtStorage, mtStorage2)
}
