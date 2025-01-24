package loaders

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/piprate/json-gold/ld"
)

type cachedRemoteDocument struct {
	remoteDocument *ld.RemoteDocument
	expireTime     time.Time
}

type memoryCacheEngine struct {
	m         sync.RWMutex
	cache     map[string]*cachedRemoteDocument
	embedDocs map[string]*ld.RemoteDocument
}

func (m *memoryCacheEngine) Get(
	key string) (*ld.RemoteDocument, time.Time, error) {

	if m.embedDocs != nil {
		doc, ok := m.embedDocs[key]
		if ok {
			return doc, time.Now().Add(time.Hour), nil
		}
	}

	m.m.RLock()
	defer m.m.RUnlock()

	cd, ok := m.cache[key]
	if ok {
		return cd.remoteDocument, cd.expireTime, nil
	}
	return nil, time.Time{}, ErrCacheMiss
}

func (m *memoryCacheEngine) Set(key string, doc *ld.RemoteDocument,
	expireTime time.Time) error {

	if m.embedDocs != nil {
		// if we have the document in the embedded cache, do not overwrite it
		// with the new value.
		_, ok := m.embedDocs[key]
		if ok {
			return nil
		}
	}

	m.m.Lock()
	defer m.m.Unlock()

	m.cache[key] = &cachedRemoteDocument{
		remoteDocument: doc,
		expireTime:     expireTime,
	}

	return nil
}

type MemoryCacheEngineOption func(*memoryCacheEngine) error

func WithEmbeddedDocumentBytes(u string, doc []byte) MemoryCacheEngineOption {
	return func(engine *memoryCacheEngine) error {
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

func NewMemoryCacheEngine(
	opts ...MemoryCacheEngineOption) (CacheEngine, error) {

	e := &memoryCacheEngine{
		cache: make(map[string]*cachedRemoteDocument),
	}

	for _, opt := range opts {
		err := opt(e)
		if err != nil {
			return nil, err
		}
	}

	return e, nil
}
