package c_polygonid

import (
	"errors"
	"os"
	"path"
	"testing"

	"github.com/dgraph-io/badger"
	"github.com/stretchr/testify/require"
)

func getBadgerPath(t testing.TB) string {
	cachePath, err := os.UserCacheDir()
	require.NoError(t, err)
	cachePath = path.Join(cachePath, "c-polygonid-cache")
	return cachePath
}

func withBadger(t testing.TB, disableLogger bool) (*badger.DB, func()) {
	badgerPath := getBadgerPath(t)
	opts := badger.DefaultOptions(badgerPath)
	if disableLogger {
		opts.Logger = nil
	}
	db, err := badger.Open(opts)
	require.NoError(t, err)

	return db, func() {
		err = db.Close()
		require.NoError(t, err)
	}
}

func doWithBadger(t testing.TB, db *badger.DB) {
	err := db.View(func(txn *badger.Txn) error {
		i, err := txn.Get([]byte("key1"))
		var v string
		if errors.Is(err, badger.ErrKeyNotFound) {
			// pass - no value
		} else if err != nil {

		} else {
			v = i.String()
		}

		_ = v
		//t.Log(v)
		return nil
	})
	require.NoError(t, err)

	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte("key1"), []byte("val1"))
	})
	require.NoError(t, err)
}

func BenchmarkBadgerWithOpening(b *testing.B) {
	for i := 0; i < b.N; i++ {
		func() {
			db, cleanup := withBadger(b, true)
			defer cleanup()
			doWithBadger(b, db)
		}()
	}
}

func BenchmarkBadgerWithoutOpening(b *testing.B) {
	db, cleanup := withBadger(b, true)
	defer cleanup()

	for i := 0; i < b.N; i++ {
		doWithBadger(b, db)
		err := db.Sync()
		require.NoError(b, err)
	}
}
