package c_polygonid

import (
	"log/slog"
	"os"
	"path"
	"sync"

	"github.com/dgraph-io/badger/v4"
)

var globalDB *badger.DB
var dbCnt int
var dbCond = sync.NewCond(&sync.Mutex{})

func CleanCache() (err error) {
	dbCond.L.Lock()
	for dbCnt != 0 {
		dbCond.Wait()
	}
	defer dbCond.L.Unlock()

	db, err := openDB()
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

func getCacheDB() (*badger.DB, func(), error) {
	dbCond.L.Lock()
	defer dbCond.L.Unlock()

	err := maybeOpenDB()
	if err != nil {
		return nil, nil, err
	}

	// Close the DB only once per calling getCacheDB().
	var once sync.Once

	releaseDB := func() {
		once.Do(func() {
			dbCond.L.Lock()
			defer dbCond.L.Unlock()

			dbCnt--
			if dbCnt == 0 {
				err2 := globalDB.Close()
				if err2 != nil {
					slog.Error("failed to close db", "err", err2)
				}
				globalDB = nil
			}

			dbCond.Broadcast()
		})
	}

	return globalDB, releaseDB, nil
}

// If globalDB is nil, open a new DB, assign it to globalDB.
// Also increment dbCnt.
// DANGER: This function is not thread-safe and should be called only when
// dbCond.L is locked. Use getCacheDB() instead.
func maybeOpenDB() error {
	if globalDB != nil {
		dbCnt++
		return nil
	}

	db, err := openDB()
	if err != nil {
		return err
	}

	globalDB = db
	dbCnt = 1

	return nil
}

func openDB() (*badger.DB, error) {
	badgerPath, err := getBadgerPath()
	if err != nil {
		return nil, err
	}

	opts := badger.DefaultOptions(badgerPath)

	return badger.Open(opts)
}

func getBadgerPath() (string, error) {
	cachePath, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	cachePath = path.Join(cachePath, "c-polygonid-cache")
	return cachePath, nil
}
