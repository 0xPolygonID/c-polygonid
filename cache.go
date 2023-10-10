package c_polygonid

import (
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
