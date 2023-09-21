package c_polygonid

import (
	"log/slog"
	"os"
	"path"
	"sync"

	"github.com/dgraph-io/badger"
)

var db *badger.DB
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
			err := db.Close()
			if err != nil {
				slog.Error("failed to close db", "err", err)
			}
			db = nil
		}
	}

	if db != nil {
		dbCnt++
		return db, releaseDB, nil
	}

	badgerPath, err := getBadgerPath()
	if err != nil {
		return nil, nil, err
	}
	opts := badger.DefaultOptions(badgerPath)
	db, err = badger.Open(opts)
	if err != nil {
		return nil, nil, err
	}

	dbCnt = 1
	return db, releaseDB, nil
}

func getBadgerPath() (string, error) {
	cachePath, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	cachePath = path.Join(cachePath, "c-polygonid-cache")
	return cachePath, nil
}
