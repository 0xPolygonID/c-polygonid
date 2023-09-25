package c_polygonid

import (
	"errors"
	"testing"

	"github.com/dgraph-io/badger/v4"
	"github.com/stretchr/testify/require"
)

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
			db, cleanup, err := getCacheDB()
			require.NoError(b, err)
			defer cleanup()
			doWithBadger(b, db)
		}()
	}
}

func BenchmarkBadgerWithoutOpening(b *testing.B) {
	db, cleanup, err := getCacheDB()
	require.NoError(b, err)
	b.Cleanup(cleanup)

	for i := 0; i < b.N; i++ {
		doWithBadger(b, db)
		err := db.Sync()
		require.NoError(b, err)
	}
}

func TestBadger(t *testing.T) {
	dbPath, err := getBadgerPath()
	require.NoError(t, err)

	t.Log(dbPath)

	db, cleanup, err := getCacheDB()
	require.NoError(t, err)
	defer cleanup()

	doWithBadger(t, db)
}

func TestGetCacheDB(t *testing.T) {
	db1, close1, err := getCacheDB()
	require.NoError(t, err)
	db2, close2, err := getCacheDB()
	require.NoError(t, err)

	require.Equal(t, db1, db2)

	func() {
		dbM.Lock()
		defer dbM.Unlock()
		require.Equal(t, 2, dbCnt)
		require.NotNil(t, db)
	}()

	close1()

	func() {
		dbM.Lock()
		defer dbM.Unlock()
		require.Equal(t, 1, dbCnt)
		require.NotNil(t, db)
	}()

	close2()

	func() {
		dbM.Lock()
		defer dbM.Unlock()
		require.Equal(t, 0, dbCnt)
		require.Nil(t, db)
	}()
}
