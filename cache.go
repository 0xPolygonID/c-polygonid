package c_polygonid

import (
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/dgraph-io/badger/v4"
	"github.com/iden3/go-iden3-auth/v2/cache"
	"github.com/iden3/go-iden3-auth/v2/state"
)

var badgerLogger badger.Logger = nil

var openedDBs = make(map[string]*badger.DB)
var openedDBsCnts = make(map[string]int)
var dbCond = sync.NewCond(&sync.Mutex{})

func CleanCache(cacheDir string) (err error) {
	cacheDir, err = createNormalizedCacheDir(cacheDir)
	if err != nil {
		return err
	}

	dbCond.L.Lock()
	for openedDBsCnts[cacheDir] != 0 {
		dbCond.Wait()
	}
	defer dbCond.L.Unlock()

	db, err := openDB(cacheDir)
	if err != nil {
		return err
	}
	defer func() {
		err2 := db.Close()
		if err2 != nil {
			if err == nil {
				err = err2
			} else {
				slog.Error("failed to close db", "err", err2)
			}
		}
	}()

	return db.DropAll()
}

// Normalize the directory path and create it if it doesn't exist.
func createNormalizedCacheDir(d string) (string, error) {
	if d == "" {
		var err error
		d, err = os.UserCacheDir()
		if err != nil {
			return "", err
		}
	}

	normDir, err := filepath.EvalSymlinks(d)
	if errors.Is(err, os.ErrNotExist) {
		err = os.MkdirAll(d, 0700)
		if err != nil {
			return "", err
		}
		normDir, err = filepath.EvalSymlinks(d)
	}

	return normDir, err
}

func getCacheDB(cacheDir string) (*badger.DB, func(), error) {
	var err error
	cacheDir, err = createNormalizedCacheDir(cacheDir)
	if err != nil {
		return nil, nil, err
	}

	dbCond.L.Lock()
	defer dbCond.L.Unlock()

	err = maybeOpenDB(cacheDir)
	if err != nil {
		return nil, nil, err
	}

	// Close the DB only once per calling getCacheDB().
	var once sync.Once

	releaseDB := func() {
		once.Do(func() {
			dbCond.L.Lock()
			defer dbCond.L.Unlock()

			cnt := openedDBsCnts[cacheDir]
			cnt--
			if cnt == 0 {
				err2 := openedDBs[cacheDir].Close()
				if err2 != nil {
					slog.Error("failed to close db", "err", err2)
				}
				delete(openedDBs, cacheDir)
				delete(openedDBsCnts, cacheDir)
			} else {
				openedDBsCnts[cacheDir] = cnt
			}

			dbCond.Broadcast()
		})
	}

	return openedDBs[cacheDir], releaseDB, nil
}

// If openedDBs[cacheDir] is nil, open a new DB and increment
// openedDBsCnts[cacheDir].
// DANGER: This function is not thread-safe and should be called only when
// dbCond.L is locked. Use getCacheDB() instead.
func maybeOpenDB(cacheDir string) error {
	if openedDBs[cacheDir] != nil {
		openedDBsCnts[cacheDir]++
		return nil
	}

	db, err := openDB(cacheDir)
	if err != nil {
		return err
	}

	openedDBs[cacheDir] = db
	openedDBsCnts[cacheDir]++

	return nil
}

func openDB(cacheDir string) (*badger.DB, error) {
	badgerPath := path.Join(cacheDir, "c-polygonid-cache")

	opts := badger.DefaultOptions(badgerPath).
		WithValueLogFileSize(128 * 1024 * 1024)
	if badgerLogger != nil {
		opts.Logger = badgerLogger
	}

	return badger.Open(opts)
}

type AuthStateCacheWrapper struct {
	DB *badger.DB
}

// Get retrieves a ResolvedState from the cache by key.
// Returns the value and true if found, or zero value and false if not found.
func (c *AuthStateCacheWrapper) Get(key string) (state.ResolvedState, bool) {
	var result state.ResolvedState
	err := c.DB.View(func(txn *badger.Txn) error {
		item, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		return item.Value(func(val []byte) error {
			return json.Unmarshal(val, &result)
		})
	})

	if err != nil {
		return state.ResolvedState{}, false
	}
	return result, true
}

// Set stores a ResolvedState in the cache with the given key.
func (c *AuthStateCacheWrapper) Set(key string, value state.ResolvedState, _ ...cache.SetOptions) {
	data, err := json.Marshal(value)
	if err != nil {
		return
	}

	_ = c.DB.Update(func(txn *badger.Txn) error {
		entry := badger.NewEntry([]byte(key), data)
		return txn.SetEntry(entry)
	})
}

// Delete removes an entry from the cache by key.
func (c *AuthStateCacheWrapper) Delete(key string) {
	_ = c.DB.Update(func(txn *badger.Txn) error {
		return txn.Delete([]byte(key))
	})
}

// Clear removes all entries from the cache.
func (c *AuthStateCacheWrapper) Clear() {
	_ = c.DB.DropAll()
}

// Len returns the number of entries in the cache.
func (c *AuthStateCacheWrapper) Len() int {
	count := 0
	err := c.DB.View(func(txn *badger.Txn) error {
		opts := badger.DefaultIteratorOptions
		opts.PrefetchValues = false
		it := txn.NewIterator(opts)
		defer it.Close()

		for it.Rewind(); it.Valid(); it.Next() {
			count++
		}
		return nil
	})

	if err != nil {
		return 0
	}
	return count
}
