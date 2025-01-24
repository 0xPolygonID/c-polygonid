package merklize

import (
	"bytes"
	"context"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
)

const rdfEntryEncodingVersion = 1

type entryType uint8

const (
	entryTypeInt64  entryType = 0
	entryTypeBool   entryType = 1
	entryTypeString entryType = 2
	entryTypeTime   entryType = 3
	entryTypeBigInt entryType = 4
)

func doEncode[T rdfEntryValueType](enc *gob.Encoder, d entryType, v T) error {
	err := enc.Encode(d)
	if err != nil {
		return err
	}
	err = enc.Encode(v)
	if err != nil {
		return err
	}
	return nil
}

func doDecode[T rdfEntryValueType](dec *gob.Decoder) (any, error) {
	var x T
	err := dec.Decode(&x)
	if err != nil {
		return nil, err
	}
	return x, nil
}

func (e *RDFEntry) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	err := enc.Encode(rdfEntryEncodingVersion)
	if err != nil {
		return nil, err
	}

	err = enc.Encode(e.key.parts)
	if err != nil {
		return nil, err
	}

	switch v := e.value.(type) {
	case int64:
		err = doEncode(enc, entryTypeInt64, v)
	case int:
		err = doEncode(enc, entryTypeInt64, int64(v))
	case bool:
		err = doEncode(enc, entryTypeBool, v)
	case string:
		err = doEncode(enc, entryTypeString, v)
	case time.Time:
		err = doEncode(enc, entryTypeTime, v)
	case *big.Int:
		err = doEncode(enc, entryTypeBigInt, v)
	default:
		err = fmt.Errorf("unsupported entry type: %T", e)
	}
	if err != nil {
		return nil, err
	}

	err = enc.Encode(e.datatype)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (e *RDFEntry) UnmarshalBinary(in []byte) error {
	dec := gob.NewDecoder(bytes.NewReader(in))

	var encVersion int

	err := dec.Decode(&encVersion)
	if err != nil {
		return err
	}

	if encVersion != rdfEntryEncodingVersion {
		return fmt.Errorf("wrong encoding version: %v", encVersion)
	}

	e.key.hasher = e.getHasher()
	if e.hasher == nil {
		e.hasher = e.key.hasher
	}
	err = dec.Decode(&e.key.parts)
	if err != nil {
		return err
	}

	var tp entryType
	err = dec.Decode(&tp)
	if err != nil {
		return err
	}
	switch tp {
	case entryTypeInt64:
		e.value, err = doDecode[int64](dec)
	case entryTypeBool:
		e.value, err = doDecode[bool](dec)
	case entryTypeString:
		e.value, err = doDecode[string](dec)
	case entryTypeTime:
		e.value, err = doDecode[time.Time](dec)
	case entryTypeBigInt:
		e.value, err = doDecode[*big.Int](dec)
	default:
		err = fmt.Errorf("unsupported entry type: %T", e)
	}
	if err != nil {
		return err
	}

	err = dec.Decode(&e.datatype)
	if err != nil {
		return err
	}

	return nil
}

const mzEncodingVersion = 1

func MerklizerFromBytes(in []byte, opts ...MerklizeOption) (*Merklizer, error) {
	mz := &Merklizer{
		safeMode: true,
		hasher:   defaultHasher,
	}
	for _, o := range opts {
		o(mz)
	}

	err := mz.UnmarshalBinary(in)
	return mz, err
}

func (mz *Merklizer) MarshalBinary() ([]byte, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)

	err := enc.Encode(mzEncodingVersion)
	if err != nil {
		return nil, err
	}

	err = enc.Encode(mz.srcDoc)
	if err != nil {
		return nil, err
	}

	compactedBytes, err := json.Marshal(mz.compacted)
	if err != nil {
		return nil, err
	}
	err = enc.Encode(compactedBytes)
	if err != nil {
		return nil, err
	}

	root := mz.mt.Root().BigInt()
	err = enc.Encode(root)
	if err != nil {
		return nil, err
	}

	err = enc.Encode(len(mz.entries))
	if err != nil {
		return nil, err
	}

	for k, e := range mz.entries {
		err = enc.Encode(k)
		if err != nil {
			return nil, err
		}

		e := e // actually not needed, but lint complains
		err = enc.Encode(&e)
		if err != nil {
			return nil, err
		}
	}

	err = enc.Encode(mz.safeMode)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func (mz *Merklizer) UnmarshalBinary(in []byte) error {
	enc := gob.NewDecoder(bytes.NewReader(in))

	var encodingVersion int
	err := enc.Decode(&encodingVersion)
	if err != nil {
		return err
	}

	if mzEncodingVersion != encodingVersion {
		return fmt.Errorf("wrong encoding version: %v", encodingVersion)
	}

	err = enc.Decode(&mz.srcDoc)
	if err != nil {
		return err
	}

	var compactedBytes []byte
	err = enc.Decode(&compactedBytes)
	if err != nil {
		return err
	}
	err = json.Unmarshal(compactedBytes, &mz.compacted)
	if err != nil {
		return err
	}

	var root *big.Int
	err = enc.Decode(&root)
	if err != nil {
		return err
	}

	addToMT := false

	if mz.hasher == nil {
		mz.hasher = defaultHasher
	}

	// if merkletree is not set with options, initialize new in-memory MT.
	if mz.mt == nil {
		var mt *merkletree.MerkleTree
		mt, err = merkletree.NewMerkleTree(context.Background(),
			memory.NewMemoryStorage(), 40)
		if err != nil {
			return err
		}
		mz.mt = MerkleTreeSQLAdapter(mt)
		addToMT = true
	}

	if !addToMT && mz.mt.Root().BigInt().Cmp(root) != 0 {
		return errors.New("root hash mismatch")
	}

	var entriesLen int
	err = enc.Decode(&entriesLen)
	if err != nil {
		return err
	}

	entries := make([]RDFEntry, entriesLen)
	mz.entries = make(map[string]RDFEntry, entriesLen)

	for i := 0; i < entriesLen; i++ {
		var key string
		err = enc.Decode(&key)
		if err != nil {
			return err
		}

		var p Path
		p, err = mz.Options().NewPath("")
		if err != nil {
			return err
		}
		entries[i], err = mz.Options().NewRDFEntry(p, "")
		if err != nil {
			return err
		}

		err = enc.Decode(&entries[i])
		if err != nil {
			return err
		}

		mz.entries[key] = entries[i]
	}

	if addToMT {
		err = AddEntriesToMerkleTree(context.Background(), mz.mt, entries)
		if err != nil {
			return err
		}
	}

	err = enc.Decode(&mz.safeMode)
	if err != nil {
		return err
	}

	return nil
}

type gobJTp uint8

const (
	gobJTpNull  gobJTp = 0
	gobJTpList  gobJTp = 1
	gobJTpMap   gobJTp = 2
	gobJTpOther gobJTp = 3
)

func gobJSONObjectEncode(enc *gob.Encoder, e any) error {
	var err error
	switch v := e.(type) {
	case nil:
		err = enc.Encode(gobJTpNull)
		if err != nil {
			return err
		}
	case []any:
		err = enc.Encode(gobJTpList)
		if err != nil {
			return err
		}
		err = enc.Encode(len(v))
		if err != nil {
			return err
		}
		for _, e2 := range v {
			err = gobJSONObjectEncode(enc, e2)
			if err != nil {
				return err
			}
		}
	case map[string]any:
		err = enc.Encode(gobJTpMap)
		if err != nil {
			return err
		}
		err = gobJSONMapEncode(enc, v)
		if err != nil {
			return err
		}
	default:
		err = enc.Encode(gobJTpOther)
		if err != nil {
			return err
		}
		err = enc.Encode(&e)
		if err != nil {
			return err
		}
	}
	return nil
}

func gobJSONMapEncode(enc *gob.Encoder, o map[string]any) error {
	err := enc.Encode(len(o))
	if err != nil {
		return err
	}

	for k, v := range o {
		err = enc.Encode(k)
		if err != nil {
			return err
		}
		err = gobJSONObjectEncode(enc, v)
		if err != nil {
			return err
		}
	}

	return nil
}

func gobJSONObjectDecode(dec *gob.Decoder) (any, error) {
	var tp gobJTp
	err := dec.Decode(&tp)
	if err != nil {
		return nil, err
	}

	switch tp {
	case gobJTpNull:
		return nil, nil
	case gobJTpMap:
		return gobJSONMapDecode(dec)
	case gobJTpList:
		return gobJSONListDecode(dec)
	case gobJTpOther:
		var e any
		err = dec.Decode(&e)
		if err != nil {
			return nil, err
		}
		return e, nil
	default:
		return nil, errors.New("unexpected type")
	}
}

func gobJSONListDecode(dec *gob.Decoder) ([]any, error) {
	var ln int
	err := dec.Decode(&ln)
	if err != nil {
		return nil, err
	}
	var l = make([]any, ln)
	for i := 0; i < ln; i++ {
		l[i], err = gobJSONObjectDecode(dec)
		if err != nil {
			return nil, err
		}
	}
	return l, nil
}

func gobJSONMapDecode(dec *gob.Decoder) (map[string]any, error) {
	var ln int
	err := dec.Decode(&ln)
	if err != nil {
		return nil, err
	}

	var m = make(map[string]any, ln)
	for i := 0; i < ln; i++ {
		var k string
		err = dec.Decode(&k)
		if err != nil {
			return nil, err
		}
		m[k], err = gobJSONObjectDecode(dec)
		if err != nil {
			return nil, err
		}
	}

	return m, nil
}
