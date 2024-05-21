package c_polygonid

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
)

var revStatusCacheMutex sync.RWMutex

const issuerStateTTL = 5 * time.Minute

func toHash(in *string) (merkletree.Hash, error) {
	if in == nil || *in == "" {
		return merkletree.HashZero, nil
	}
	h, err := merkletree.NewHashFromHex(*in)
	if err != nil {
		return merkletree.Hash{}, err
	}
	return *h, nil
}

func cacheKeyIssuerState(issuerDID *w3c.DID) string {
	return fmt.Sprintf("issuer-state-%v", issuerDID.String())
}

func cacheKeyRevStatus(revTreeRoot merkletree.Hash,
	credStatus verifiable.CredentialStatus) string {

	return fmt.Sprintf("rev-status-%s-%s-%s-%d", hex.EncodeToString(revTreeRoot[:]),
		credStatus.ID, credStatus.Type, credStatus.RevocationNonce)
}

func cacheKeyRevTreeEntries(revTreeRoot merkletree.Hash) string {
	return fmt.Sprintf("rev-tree-entries-%s",
		hex.EncodeToString(revTreeRoot[:]))
}

type treeStateEntry struct {
	TreeState verifiable.TreeState `json:"treeState"`
	CreatedAt time.Time            `json:"createdAt"`
}

func putIssuerStateToCache(db *badger.DB, issuerDID *w3c.DID,
	issuerState verifiable.TreeState) error {

	key := []byte(cacheKeyIssuerState(issuerDID))
	value, err := json.Marshal(treeStateEntry{
		TreeState: issuerState,
		CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	return db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}

// may return badger.ErrKeyNotFound if state is not found in cache
func getIssuerStateFromCache(db *badger.DB,
	issuerDID *w3c.DID) (verifiable.TreeState, time.Time, error) {

	var stateEntry treeStateEntry
	err := db.View(func(txn *badger.Txn) error {
		itm, err2 := txn.Get([]byte(cacheKeyIssuerState(issuerDID)))
		if err2 != nil {
			return err2
		}
		return itm.Value(func(val []byte) error {
			return json.Unmarshal(val, &stateEntry)
		})
	})
	if err != nil {
		return verifiable.TreeState{}, time.Time{}, err
	}

	return stateEntry.TreeState, stateEntry.CreatedAt, nil
}

type registryBuilder func(ctx context.Context, cfg PerChainConfig) (
	*verifiable.CredentialStatusResolverRegistry, func(), error)

func resolveRevStatus(ctx context.Context, chainCfg PerChainConfig,
	issuerDID *w3c.DID, credStatus verifiable.CredentialStatus,
	regBuilder registryBuilder) (verifiable.RevocationStatus, error) {

	if regBuilder == nil {
		return verifiable.RevocationStatus{},
			errors.New("registry builder is null")
	}
	resolversRegistry, registryCleanupFn, err := regBuilder(ctx,
		chainCfg)
	if err != nil {
		return verifiable.RevocationStatus{}, err
	}
	defer registryCleanupFn()

	resolver, err := resolversRegistry.Get(credStatus.Type)
	if err != nil {
		return verifiable.RevocationStatus{}, err
	}

	ctx = verifiable.WithIssuerDID(ctx, issuerDID)
	return resolver.Resolve(ctx, credStatus)
}

func resolveRevStatusAndCache(ctx context.Context, db *badger.DB,
	chainCfg PerChainConfig, issuerDID *w3c.DID,
	credStatus verifiable.CredentialStatus,
	regBuilder registryBuilder) (verifiable.RevocationStatus, error) {

	revStatus, err := resolveRevStatus(ctx, chainCfg, issuerDID, credStatus,
		regBuilder)
	if err != nil {
		return verifiable.RevocationStatus{}, err
	}

	revStatusCacheMutex.Lock()
	defer revStatusCacheMutex.Unlock()

	var oldState verifiable.TreeState
	var hasOldState bool
	var oldRevTreeRoot merkletree.Hash
	oldState, _, err = getIssuerStateFromCache(db, issuerDID)
	if errors.Is(err, badger.ErrKeyNotFound) {
		hasOldState = false
	} else if err != nil {
		return verifiable.RevocationStatus{}, err
	} else {
		hasOldState = true
		oldRevTreeRoot, err = toHash(oldState.RevocationTreeRoot)
		if err != nil {
			return verifiable.RevocationStatus{}, err
		}
	}

	var newRevTreeRoot merkletree.Hash
	newRevTreeRoot, err = toHash(revStatus.Issuer.RevocationTreeRoot)
	if err != nil {
		return verifiable.RevocationStatus{}, err
	}

	if hasOldState && newRevTreeRoot != oldRevTreeRoot {
		err = removeExpiredRevStatusFromCache(db, oldRevTreeRoot)
		if err != nil {
			return verifiable.RevocationStatus{}, err
		}
	}

	err = putIssuerStateToCache(db, issuerDID, revStatus.Issuer)
	if err != nil {
		return verifiable.RevocationStatus{}, err
	}

	err = putRevProofToCache(db, newRevTreeRoot, credStatus, revStatus.MTP)
	if err != nil {
		return verifiable.RevocationStatus{}, err
	}

	return revStatus, nil
}

func removeExpiredRevStatusFromCache(db *badger.DB,
	revTreeRoot merkletree.Hash) error {

	treeEntriesKey := cacheKeyRevTreeEntries(revTreeRoot)
	return db.Update(func(txn *badger.Txn) error {
		ent, err := txn.Get([]byte(treeEntriesKey))
		if errors.Is(err, badger.ErrKeyNotFound) {
			return nil
		} else if err != nil {
			return err
		}

		var treeProofs []string
		err = ent.Value(func(val []byte) error {
			return json.Unmarshal(val, &treeProofs)
		})
		if err != nil {
			return err
		}
		for _, k := range treeProofs {
			err = txn.Delete([]byte(k))
			if err != nil {
				return err
			}
		}
		return txn.Delete([]byte(treeEntriesKey))
	})
}

func putRevProofToCache(db *badger.DB, revTreeRoot merkletree.Hash,
	credStatus verifiable.CredentialStatus, revProof merkletree.Proof) error {

	treeEntriesKey := cacheKeyRevTreeEntries(revTreeRoot)
	revStatusKey := cacheKeyRevStatus(revTreeRoot, credStatus)

	return db.Update(func(txn *badger.Txn) error {
		var treeProofs []string
		ent, err := txn.Get([]byte(treeEntriesKey))
		if errors.Is(err, badger.ErrKeyNotFound) {
		} else if err != nil {
			return err
		} else {
			err = ent.Value(func(val []byte) error {
				return json.Unmarshal(val, &treeProofs)
			})
			if err != nil {
				return err
			}
		}

		var val []byte
		if !slices.Contains(treeProofs, revStatusKey) {
			treeProofs = append(treeProofs, revStatusKey)
			val, err = json.Marshal(treeProofs)
			if err != nil {
				return err
			}
			err = txn.Set([]byte(treeEntriesKey), val)
			if err != nil {
				return err
			}
		}

		val, err = json.Marshal(revProof)
		if err != nil {
			return err
		}
		return txn.Set([]byte(revStatusKey), val)
	})
}

func getRevProofFromCache(db *badger.DB, revTreeRoot merkletree.Hash,
	credStatus verifiable.CredentialStatus) (merkletree.Proof, error) {

	var revProof merkletree.Proof
	err := db.View(func(txn *badger.Txn) error {
		itm, err2 := txn.Get([]byte(cacheKeyRevStatus(revTreeRoot, credStatus)))
		if err2 != nil {
			return err2
		}
		return itm.Value(func(val []byte) error {
			return json.Unmarshal(val, &revProof)
		})
	})
	if err != nil {
		return merkletree.Proof{}, err
	}
	return revProof, nil
}

func cachedResolve(ctx context.Context, chainCfg PerChainConfig,
	issuerDID *w3c.DID, credStatus verifiable.CredentialStatus,
	regBuilder registryBuilder) (verifiable.RevocationStatus, error) {

	cache, cacheCleanup, err := getCacheDB()
	if err != nil {
		// Cache engine is not available, so resolve without cache
		return resolveRevStatus(ctx, chainCfg, issuerDID, credStatus,
			regBuilder)
	}
	defer cacheCleanup()

	if issuerDID == nil {
		return verifiable.RevocationStatus{}, errors.New("issuer DID is null")
	}

	var revStatus verifiable.RevocationStatus
	var createdAt time.Time
	revStatus.Issuer, createdAt, err = getIssuerStateFromCache(cache, issuerDID)
	if errors.Is(err, badger.ErrKeyNotFound) || (err == nil && createdAt.Before(time.Now().Add(-issuerStateTTL))) {
		return resolveRevStatusAndCache(ctx, cache, chainCfg, issuerDID,
			credStatus, regBuilder)
	} else if err != nil {
		return verifiable.RevocationStatus{}, err
	}

	var revTreeRoot merkletree.Hash
	revTreeRoot, err = toHash(revStatus.Issuer.RevocationTreeRoot)
	if err != nil {
		return verifiable.RevocationStatus{}, err
	}

	revStatus.MTP, err = getRevProofFromCache(cache, revTreeRoot, credStatus)
	if errors.Is(err, badger.ErrKeyNotFound) {
		return resolveRevStatusAndCache(ctx, cache, chainCfg, issuerDID,
			credStatus, regBuilder)
	} else if err != nil {
		return verifiable.RevocationStatus{}, err
	}

	return revStatus, nil
}
