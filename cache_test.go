package c_polygonid

import (
	"errors"
	"sync"
	"testing"
	"time"

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

type testBadgerLogger struct {
	t      testing.TB
	silent bool
}

func (t *testBadgerLogger) Errorf(s string, i ...interface{}) {
	if t.silent {
		return
	}
	t.t.Errorf("[BADGER ERROR]"+s, i...)
}

func (t *testBadgerLogger) Warningf(s string, i ...interface{}) {
	if t.silent {
		return
	}
	t.t.Logf("[BADGER WARNING]"+s, i...)
}

func (t *testBadgerLogger) Infof(s string, i ...interface{}) {
	if t.silent {
		return
	}
	t.t.Logf("[BADGER INFO]"+s, i...)
}

func (t *testBadgerLogger) Debugf(s string, i ...interface{}) {
	if t.silent {
		return
	}
	t.t.Logf("[BADGER DEBUG]"+s, i...)
}

func mockBadgerLog(t testing.TB) {
	orig := badgerLogger
	badgerLogger = &testBadgerLogger{t, true}
	t.Cleanup(func() {
		badgerLogger = orig
	})
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
	mockBadgerLog(t)

	dbPath, err := getBadgerPath()
	require.NoError(t, err)

	t.Log(dbPath)

	db, cleanup, err := getCacheDB()
	require.NoError(t, err)
	defer cleanup()

	doWithBadger(t, db)
}

func TestGetCacheDB(t *testing.T) {
	mockBadgerLog(t)
	db1, close1, err := getCacheDB()
	require.NoError(t, err)
	db2, close2, err := getCacheDB()
	require.NoError(t, err)

	require.Equal(t, db1, db2)

	func() {
		dbCond.L.Lock()
		defer dbCond.L.Unlock()
		require.Equal(t, 2, dbCnt)
		require.NotNil(t, globalDB)
	}()

	close1()

	func() {
		dbCond.L.Lock()
		defer dbCond.L.Unlock()
		require.Equal(t, 1, dbCnt)
		require.NotNil(t, globalDB)
	}()

	close2()

	func() {
		dbCond.L.Lock()
		defer dbCond.L.Unlock()
		require.Equal(t, 0, dbCnt)
		require.Nil(t, globalDB)
	}()
}

func get(db *badger.DB, key string) string {
	var v string
	err := db.View(func(txn *badger.Txn) error {
		i, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		return i.Value(func(val []byte) error {
			v = string(val)
			return nil
		})
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return ""
	}
	if err != nil {
		panic(err)
	}
	return v
}

func set(db *badger.DB, key string, value string) {
	err := db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), []byte(value))
	})
	if err != nil {
		panic(err)
	}
}

func TestCleanCache(t *testing.T) {
	mockBadgerLog(t)
	db1, close1, err := getCacheDB()
	require.NoError(t, err)

	set(db1, "key1", "val1")

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		err2 := CleanCache()
		if err2 != nil {
			t.Error(err2)
		}
	}()

	time.Sleep(10 * time.Millisecond)

	db2, close2, err := getCacheDB()
	require.NoError(t, err)
	require.Equal(t, "val1", get(db2, "key1"))

	close1()
	close2()
	time.Sleep(10 * time.Millisecond)

	db3, close3, err := getCacheDB()
	require.NoError(t, err)
	require.Equal(t, "", get(db3, "key1"))
	close3()

	wg.Wait()
}

func TestMultipleCleanup(t *testing.T) {
	mockBadgerLog(t)
	_, close1, err := getCacheDB()
	require.NoError(t, err)

	require.Equal(t, 1, dbCnt)
	require.NotNil(t, globalDB)

	close1()
	close1()
	dbCond.L.Lock()
	defer dbCond.L.Unlock()

	require.Equal(t, 0, dbCnt)
	require.Nil(t, globalDB)
}
