package c_polygonid

import (
	"encoding/json"
	"log/slog"
	"os"
	"path"
	"sync"

	"github.com/dgraph-io/badger/v4"
)

var globalDB *badger.DB
var dbM sync.Mutex
var dbCnt int

func getCacheDB() (*badger.DB, func(), error) {
	dbM.Lock()
	defer dbM.Unlock()

	releaseDB := func() {
		dbM.Lock()
		defer dbM.Unlock()

		dbCnt--
		if dbCnt == 0 {
			err := globalDB.Close()
			if err != nil {
				slog.Error("failed to close db", "err", err)
			}
			globalDB = nil
		}
	}

	if globalDB != nil {
		dbCnt++
		return globalDB, releaseDB, nil
	}

	badgerPath, err := getBadgerPath()
	if err != nil {
		return nil, nil, err
	}
	opts := badger.DefaultOptions(badgerPath)
	globalDB, err = badger.Open(opts)
	if err != nil {
		return nil, nil, err
	}

	dbCnt = 1
	return globalDB, releaseDB, nil
}

func getBadgerPath() (string, error) {
	cachePath, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	cachePath = path.Join(cachePath, "c-polygonid-cache")
	return cachePath, nil
}

func getRemoteDocumentFromCache(db *badger.DB,
	key []byte) (cachedRemoteDocument, error) {

	var doc cachedRemoteDocument
	var value []byte

	err := db.View(func(txn *badger.Txn) error {
		entry, err := txn.Get(key)
		if err != nil {
			return err
		}
		value, err = entry.ValueCopy(nil)
		return err
	})
	if err != nil {
		return doc, err
	}

	return doc, json.Unmarshal(value, &doc)
}

func putRemoteDocumentToCache(db *badger.DB, key []byte,
	doc cachedRemoteDocument) error {

	value, err := json.Marshal(doc)
	if err != nil {
		return err
	}

	return db.Update(func(txn *badger.Txn) error {
		return txn.Set(key, value)
	})
}
