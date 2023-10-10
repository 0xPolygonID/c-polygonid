package c_polygonid

import (
	"testing"
	"time"

	"github.com/iden3/go-schema-processor/v2/loaders"
	"github.com/piprate/json-gold/ld"
	"github.com/stretchr/testify/require"
)

func TestGetPubRemoteDocument(t *testing.T) {
	flushCacheDB()

	cacheEng, err := newBadgerCacheEngine()
	require.NoError(t, err)

	key := "123"
	doc1, expireTime1, err := cacheEng.Get(key)
	require.EqualError(t, err, loaders.ErrCacheMiss.Error())
	require.Nil(t, doc1)
	require.True(t, expireTime1.IsZero())

	doc := &ld.RemoteDocument{
		DocumentURL: "123",
		Document:    map[string]any{"one": float64(1)},
		ContextURL:  "456",
	}
	expireTime := time.Now().Add(time.Hour)

	err = cacheEng.Set(key, doc, expireTime)
	require.NoError(t, err)

	doc2, expireTime2, err := cacheEng.Get(key)
	require.NoError(t, err)
	require.Equal(t, doc, doc2)
	require.True(t, expireTime2.Equal(expireTime))
}
