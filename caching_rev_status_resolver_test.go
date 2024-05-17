package c_polygonid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/dgraph-io/badger/v4"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/stretchr/testify/require"
)

const mockCredStatusType = verifiable.CredentialStatusType("mockCredStatus")

type mockStatusResolver struct {
	states map[string]verifiable.TreeState
	trees  map[merkletree.Hash]*merkletree.MerkleTree
}

func (m *mockStatusResolver) Resolve(ctx context.Context,
	credStatus verifiable.CredentialStatus) (verifiable.RevocationStatus, error) {

	var revStatus verifiable.RevocationStatus

	issuerDID := verifiable.GetIssuerDID(ctx)
	if issuerDID == nil {
		return revStatus, errors.New("issuer DID not found in context")
	}

	var ok bool
	revStatus.Issuer, ok = m.states[issuerDID.String()]
	if !ok {
		return revStatus, errors.New("issuer state not found")
	}

	h, err := toHash(revStatus.Issuer.RevocationTreeRoot)
	if err != nil {
		return verifiable.RevocationStatus{}, err
	}

	revTree, ok := m.trees[h]
	if !ok {
		return verifiable.RevocationStatus{},
			errors.New("revocation tree not found")
	}

	var proof *merkletree.Proof
	proof, _, err = revTree.GenerateProof(ctx, new(big.Int).SetUint64(credStatus.RevocationNonce), nil)
	if err != nil {
		return revStatus, err
	}
	revStatus.MTP = *proof

	return revStatus, nil
}

func regBuilder(states map[string]verifiable.TreeState,
	trees map[merkletree.Hash]*merkletree.MerkleTree) registryBuilder {

	return func(ctx context.Context,
		cfg PerChainConfig) (*verifiable.CredentialStatusResolverRegistry, func(), error) {

		var registry = &verifiable.CredentialStatusResolverRegistry{}

		registry.Register(mockCredStatusType, &mockStatusResolver{states, trees})
		cleanupFn := func() {
			registry.Delete(mockCredStatusType)
		}

		return registry, cleanupFn, nil
	}
}

func TestCachedResolve(t *testing.T) {
	mockBadgerLog(t)
	flushCacheDB(t)

	ctx := context.Background()
	_, err := cachedResolve(ctx, PerChainConfig{}, nil,
		verifiable.CredentialStatus{}, nil)
	require.EqualError(t, err, "issuer DID is null")

	typ, err := core.BuildDIDType(core.DIDMethodPolygonID, core.ZkEVM,
		core.Main)
	require.NoError(t, err)

	issuerDID, err := core.NewDIDFromIdenState(typ, big.NewInt(1))
	require.NoError(t, err)

	_, err = cachedResolve(ctx, PerChainConfig{}, issuerDID,
		verifiable.CredentialStatus{}, nil)
	require.EqualError(t, err, "registry builder is null")

	credStatus := verifiable.CredentialStatus{
		ID:              "id1",
		Type:            mockCredStatusType,
		RevocationNonce: 100500,
		StatusIssuer:    nil,
	}

	states := map[string]verifiable.TreeState{}
	trees := map[merkletree.Hash]*merkletree.MerkleTree{}

	revStatus, err := cachedResolve(ctx, PerChainConfig{}, issuerDID,
		credStatus, regBuilder(states, trees))
	require.EqualError(t, err, "issuer state not found")

	revTree, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
	require.NoError(t, err)
	state0, err := merkletree.HashElems(merkletree.HashZero.BigInt(),
		revTree.Root().BigInt(), merkletree.HashZero.BigInt())
	require.NoError(t, err)
	issuerState := verifiable.TreeState{
		State:              &[]string{state0.Hex()}[0],
		RootOfRoots:        nil,
		ClaimsTreeRoot:     nil,
		RevocationTreeRoot: &[]string{revTree.Root().Hex()}[0],
	}
	states[issuerDID.String()] = issuerState
	trees[*revTree.Root()] = revTree
	revStatus, err = cachedResolve(ctx, PerChainConfig{}, issuerDID,
		credStatus, regBuilder(states, trees))
	require.NoError(t, err)
	wantRevStatus0 := `{
"issuer":{
  "state":"aa99a51bb36dee7caec596ecec4e86e28ff07a0aafb6cf1ddceacc7dd288c10b",
  "revocationTreeRoot":"0000000000000000000000000000000000000000000000000000000000000000"
},
"mtp":{"existence":false,"siblings":[]}}`
	require.JSONEq(t, wantRevStatus0, toJson(revStatus))

	treeCacheKey0 := `rev-tree-entries-` + merkletree.HashZero.Hex()
	proofCacheKey0 := `rev-status-0000000000000000000000000000000000000000000000000000000000000000-id1-mockCredStatus-100500`

	// check state in cache
	t.Run("check state in cache", func(t *testing.T) {
		cacheDB := getTestCacheDB(t)

		wantTreeEntries := toJson([]string{proofCacheKey0})
		assertCacheEqual(t, cacheDB, treeCacheKey0, wantTreeEntries)
		assertCacheEqual(t, cacheDB, proofCacheKey0, `{"existence":false,"siblings":[]}`)

		cachedState, _, err2 := getIssuerStateFromCache(cacheDB, issuerDID)
		require.NoError(t, err2)
		require.Equal(t, issuerState, cachedState)
	})

	// put nonce into revTree
	err = revTree.Add(ctx, new(big.Int).SetUint64(credStatus.RevocationNonce),
		big.NewInt(0))
	require.NoError(t, err)
	trees[*revTree.Root()] = revTree
	treeCacheKey1 := `rev-tree-entries-` + revTree.Root().Hex()

	// calculate new issuer state
	issuerState.RevocationTreeRoot = &[]string{revTree.Root().Hex()}[0]
	state1, err := merkletree.HashElems(merkletree.HashZero.BigInt(),
		revTree.Root().BigInt(), merkletree.HashZero.BigInt())
	require.NoError(t, err)
	issuerState.State = &[]string{state1.Hex()}[0]
	states[issuerDID.String()] = issuerState

	// check state in cache
	t.Run("got old state from cache", func(t *testing.T) {
		revStatus, err = cachedResolve(ctx, PerChainConfig{}, issuerDID,
			credStatus, regBuilder(states, trees))
		require.NoError(t, err)
		require.JSONEq(t, wantRevStatus0, toJson(revStatus))
	})

	cacheKeyIssuer := cacheKeyIssuerState(issuerDID)
	// expire old state
	t.Run("expire old state", func(t *testing.T) {
		cacheDB := getTestCacheDB(t)
		expireTreeStateCache(t, cacheDB, cacheKeyIssuer)
	})

	wantRevStatus1 := fmt.Sprintf(`{
  "issuer":{
    "state":"%v",
    "revocationTreeRoot":"%v"
  },
  "mtp":{"existence":true,"siblings":[]}}`,
		*issuerState.State, *issuerState.RevocationTreeRoot)

	t.Run("got new rev status", func(t *testing.T) {
		revStatus, err = cachedResolve(ctx, PerChainConfig{}, issuerDID,
			credStatus, regBuilder(states, trees))
		require.NoError(t, err)
		require.JSONEq(t, wantRevStatus1, toJson(revStatus))
	})

	t.Run("old state cleaned up", func(t *testing.T) {
		cacheDB := getTestCacheDB(t)
		assertCacheDoesNotExists(t, cacheDB, treeCacheKey0)
		assertCacheDoesNotExists(t, cacheDB, proofCacheKey0)
	})

	wantRevStatus2 := fmt.Sprintf(`{
  "issuer":{
    "state":"%v",
    "revocationTreeRoot":"%v"
  },
  "mtp":{
    "existence":false,
    "siblings":[],
    "node_aux":{"key":"100500","value":"0"}
  }
}`,
		*issuerState.State, *issuerState.RevocationTreeRoot)

	t.Run("unknown rev nonce", func(t *testing.T) {
		credStatus2 := credStatus
		credStatus2.RevocationNonce += 1
		revStatus, err = cachedResolve(ctx, PerChainConfig{}, issuerDID,
			credStatus2, regBuilder(states, trees))
		require.NoError(t, err)
		require.JSONEq(t, wantRevStatus2, toJson(revStatus))

		cacheDB := getTestCacheDB(t)

		revTreeRoot := revTree.Root().Hex()
		proof1Key := `rev-status-` + revTreeRoot + `-id1-mockCredStatus-` + strconv.Itoa(int(credStatus.RevocationNonce))
		proof2Key := `rev-status-` + revTreeRoot + `-id1-mockCredStatus-` + strconv.Itoa(int(credStatus2.RevocationNonce))
		wantTreeEntries := toJson([]string{proof1Key, proof2Key})
		assertCacheEqual(t, cacheDB, treeCacheKey1, wantTreeEntries)

		assertCacheEqual(t, cacheDB, proof1Key, `{"existence":true,"siblings":[]}`)
		assertCacheEqual(t, cacheDB, proof2Key, `{"existence":false,"siblings":[],"node_aux":{"key":"100500","value":"0"}}`)
	})
}

func expireTreeStateCache(t testing.TB, cacheDB *badger.DB, key string) {
	err := cacheDB.Update(func(txn *badger.Txn) error {
		entry, err := txn.Get([]byte(key))
		require.NoError(t, err)
		entryVal, err := entry.ValueCopy(nil)
		require.NoError(t, err)
		var stateEntry treeStateEntry
		require.NoError(t, json.Unmarshal(entryVal, &stateEntry))
		stateEntry.CreatedAt = time.Now().Add(-issuerStateTTL - time.Second)
		entryVal, err = json.Marshal(stateEntry)
		require.NoError(t, txn.Set([]byte(key), entryVal))
		return nil
	})
	require.NoError(t, err)
}

func assertCacheDoesNotExists(t testing.TB, cacheDB *badger.DB, key string) {
	err := cacheDB.Update(func(txn *badger.Txn) error {
		_, err := txn.Get([]byte(key))
		require.ErrorIs(t, err, badger.ErrKeyNotFound)
		return nil
	})
	require.NoError(t, err)
}

func assertCacheEqual(t testing.TB, cacheDB *badger.DB, key string, want string) {
	err := cacheDB.View(func(txn *badger.Txn) error {
		entry, err := txn.Get([]byte(key))
		require.NoError(t, err)

		valueBytes, err := entry.ValueCopy(nil)
		require.NoError(t, err)

		require.JSONEq(t, want, string(valueBytes), string(valueBytes))

		return nil
	})
	require.NoError(t, err)
}

func toJson(obj any) string {
	bs, err := json.Marshal(obj)
	if err != nil {
		panic(err)
	}
	return string(bs)
}

func getTestCacheDB(t testing.TB) *badger.DB {
	db, cleanup, err := getCacheDB()
	require.NoError(t, err)
	t.Cleanup(cleanup)
	return db
}

func TestCacheKeyRevTreeEntries(t *testing.T) {
	key := cacheKeyRevTreeEntries(merkletree.HashZero)
	require.Equal(t, "rev-tree-entries-0000000000000000000000000000000000000000000000000000000000000000", key)
}
