package c_polygonid

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"sync"

	"github.com/iden3/go-merkletree-sql/v2"
)

type inMemoryStorage struct {
	m           sync.RWMutex
	kv          map[string]merkletree.Node
	currentRoot *merkletree.Hash
}

func newInMemoryStorage() *inMemoryStorage {
	return &inMemoryStorage{kv: make(map[string]merkletree.Node)}
}

func (m *inMemoryStorage) Get(_ context.Context, key []byte) (*merkletree.Node, error) {
	m.m.RLock()
	defer m.m.RUnlock()
	if v, ok := m.kv[string(key)]; ok {
		return &v, nil
	}
	return nil, merkletree.ErrNotFound
}

// Put inserts new node into merkletree
func (m *inMemoryStorage) Put(_ context.Context, key []byte,
	node *merkletree.Node) error {

	m.m.Lock()
	defer m.m.Unlock()
	m.kv[string(key)] = *node
	return nil
}

// GetRoot returns current merkletree root
func (m *inMemoryStorage) GetRoot(_ context.Context) (*merkletree.Hash, error) {
	m.m.RLock()
	defer m.m.RUnlock()

	if m.currentRoot != nil {
		hash := merkletree.Hash{}
		copy(hash[:], m.currentRoot[:])
		return &hash, nil
	}

	return nil, merkletree.ErrNotFound
}

// SetRoot updates current merkletree root
func (m *inMemoryStorage) SetRoot(_ context.Context, hash *merkletree.Hash) error {
	m.m.Lock()
	defer m.m.Unlock()

	root := &merkletree.Hash{}
	copy(root[:], hash[:])
	m.currentRoot = root

	return nil
}

const storageMarshalingVersion = "mem_storage_v1"

const nodeMarshalingVersion = "node_v1"

func (m *inMemoryStorage) MarshalBinary() ([]byte, error) {
	m.m.RLock()
	defer m.m.RUnlock()

	var buf bytes.Buffer
	buf.Grow(len(m.kv) * 170)
	enc := gob.NewEncoder(&buf)

	err := enc.Encode(storageMarshalingVersion)
	if err != nil {
		return nil, err
	}

	var hasRoot bool
	if m.currentRoot != nil {
		hasRoot = true
	}
	err = enc.Encode(hasRoot)
	if err != nil {
		return nil, err
	}

	if hasRoot {
		err = enc.Encode(m.currentRoot)
		if err != nil {
			return nil, err
		}
	}

	err = enc.Encode(len(m.kv))
	if err != nil {
		return nil, err
	}
	for k, v := range m.kv {
		err = enc.Encode(k)
		if err != nil {
			return nil, err
		}

		err = encodeNode(enc, v)
		if err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

func (m *inMemoryStorage) UnmarshalBinary(data []byte) error {
	m.m.Lock()
	defer m.m.Unlock()

	if len(m.kv) > 0 {
		return errors.New("unmarshal into non-empty storage")
	}

	dec := gob.NewDecoder(bytes.NewReader(data))

	var version string
	err := dec.Decode(&version)
	if err != nil {
		return err
	}

	if version != storageMarshalingVersion {
		return errors.New("unknown storage marshaling version")
	}

	var hasRoot bool
	err = dec.Decode(&hasRoot)
	if err != nil {
		return err
	}

	if hasRoot {
		err = dec.Decode(&m.currentRoot)
		if err != nil {
			return err
		}
	}

	var entriesNum int
	err = dec.Decode(&entriesNum)
	if err != nil {
		return err
	}
	for i := 0; i < entriesNum; i++ {
		var key string
		err = dec.Decode(&key)
		if err != nil {
			return err
		}

		var node merkletree.Node
		node, err = decodeNode(dec)
		if err != nil {
			return err
		}

		m.kv[key] = node
	}

	return nil
}

func encodeNode(enc *gob.Encoder, n merkletree.Node) error {
	err := enc.Encode(nodeMarshalingVersion)
	if err != nil {
		return err
	}

	err = enc.Encode(n.Type)
	if err != nil {
		return err
	}

	var flags uint8 = 0
	if n.ChildL != nil {
		flags |= 1
	}
	if n.ChildR != nil {
		flags |= 2
	}
	if n.Entry[0] != nil {
		flags |= 4
	}
	if n.Entry[1] != nil {
		flags |= 8
	}

	err = enc.Encode(flags)
	if err != nil {
		return err
	}
	if n.ChildL != nil {
		err = enc.Encode(n.ChildL)
		if err != nil {
			return err
		}
	}
	if n.ChildR != nil {
		err = enc.Encode(n.ChildR)
		if err != nil {
			return err
		}
	}
	if n.Entry[0] != nil {
		err = enc.Encode(n.Entry[0])
		if err != nil {
			return err
		}
	}
	if n.Entry[1] != nil {
		err = enc.Encode(n.Entry[1])
		if err != nil {
			return err
		}
	}
	return nil
}

func decodeNode(dec *gob.Decoder) (merkletree.Node, error) {
	var n merkletree.Node

	var version string
	err := dec.Decode(&version)
	if err != nil {
		return n, err
	}
	if version != nodeMarshalingVersion {
		return n, errors.New("unknown node marshaling version")
	}

	err = dec.Decode(&n.Type)
	if err != nil {
		return n, err
	}

	var flags uint8 = 0
	err = dec.Decode(&flags)
	if err != nil {
		return n, err
	}

	if flags&1 != 0 {
		err = dec.Decode(&n.ChildL)
		if err != nil {
			return n, err
		}
	}
	if flags&2 != 0 {
		err = dec.Decode(&n.ChildR)
		if err != nil {
			return n, err
		}
	}
	if flags&4 != 0 {
		err = dec.Decode(&n.Entry[0])
		if err != nil {
			return n, err
		}
	}
	if flags&8 != 0 {
		err = dec.Decode(&n.Entry[1])
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
