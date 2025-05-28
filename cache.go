package c_polygonid

import (
	"errors"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/dgraph-io/badger/v4"
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
		WithValueLogFileSize(256 * 1024 * 1024)
	if badgerLogger != nil {
		opts.Logger = badgerLogger
	}

	return badger.Open(opts)
}
