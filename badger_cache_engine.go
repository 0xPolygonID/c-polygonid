package c_polygonid

import (
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/dgraph-io/badger/v4"
	"github.com/iden3/go-schema-processor/v2/loaders"
	"github.com/piprate/json-gold/ld"
)

type cachedRemoteDocument struct {
	RemoteDocument *ld.RemoteDocument
	ExpireTime     time.Time
}

type badgerCacheEngine struct {
	embedDocs map[string]*ld.RemoteDocument
}

func (m *badgerCacheEngine) Get(
	key string) (*ld.RemoteDocument, time.Time, error) {

	if m.embedDocs != nil {
		doc, ok := m.embedDocs[key]
		if ok {
			return doc, time.Now().Add(time.Hour), nil
		}
	}

	db, cleanup, err := getCacheDB()
	if err != nil {
		slog.Error("can't get cache database", "err", err)
		return nil, time.Time{}, loaders.ErrCacheMiss
	}
	defer cleanup()

	var value []byte

	err = db.View(func(txn *badger.Txn) error {
		entry, err := txn.Get([]byte(key))
		if err != nil {
			return err
		}
		value, err = entry.ValueCopy(nil)
		return err
	})
	if errors.Is(err, badger.ErrKeyNotFound) {
		return nil, time.Time{}, loaders.ErrCacheMiss
	} else if err != nil {
		slog.Error("error getting remote document from cache",
			"err", err)
		return nil, time.Time{}, loaders.ErrCacheMiss
	}

	var doc cachedRemoteDocument
	err = json.Unmarshal(value, &doc)
	if err != nil {
		slog.Error("error unmarshalling cached document",
			"err", err)
		return nil, time.Time{}, loaders.ErrCacheMiss
	}

	return doc.RemoteDocument, doc.ExpireTime, nil
}

func (m *badgerCacheEngine) Set(key string, doc *ld.RemoteDocument,
	expireTime time.Time) error {

	if m.embedDocs != nil {
		// if we have the document in the embedded cache, do not overwrite it
		// with the new value.
		_, ok := m.embedDocs[key]
		if ok {
			return nil
		}
	}

	db, cleanup, err := getCacheDB()
	if err != nil {
		slog.Error("can't get cache database", "err", err)
		return nil
	}
	defer cleanup()

	value, err := json.Marshal(cachedRemoteDocument{
		RemoteDocument: doc,
		ExpireTime:     expireTime,
	})
	if err != nil {
		slog.Error("error marshalling cached document", "err", err)
		return nil
	}

	err = db.Update(func(txn *badger.Txn) error {
		return txn.Set([]byte(key), value)
	})
	if err != nil {
		slog.Error("error storing document to BadgerDB", "err", err)
	}
	return nil
}

type badgerCacheEngineOption func(*badgerCacheEngine) error

func withEmbeddedDocumentBytes(u string, doc []byte) badgerCacheEngineOption {
	return func(engine *badgerCacheEngine) error {
		if engine.embedDocs == nil {
			engine.embedDocs = make(map[string]*ld.RemoteDocument)
		}

		var rd = &ld.RemoteDocument{DocumentURL: u}
		err := json.Unmarshal(doc, &rd.Document)
		if err != nil {
			return err
		}

		engine.embedDocs[u] = rd
		return nil
	}
}

func newBadgerCacheEngine(
	opts ...badgerCacheEngineOption) (loaders.CacheEngine, error) {

	e := &badgerCacheEngine{}

	for _, opt := range opts {
		err := opt(e)
		if err != nil {
			return nil, err
		}
	}

	return e, nil
}
