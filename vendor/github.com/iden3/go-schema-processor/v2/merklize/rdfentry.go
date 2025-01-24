package merklize

import (
	"math/big"
	"time"
)

type rdfEntryValueType interface {
	int64 | string | bool | time.Time | *big.Int
}

// type RDFEntry[T RDFEntryValueType] struct {
// 	key Path
// 	// valid types are: int64, string, bool, time.Time, *big.Int
// 	value  T
// 	hasher Hasher
// }

type RDFEntry struct {
	key Path
	// valid types are: int64, string, bool, time.Time, *big.Int
	value    any
	datatype string
	hasher   Hasher
}

func NewRDFEntry(key Path, value any) (RDFEntry, error) {
	return Options{}.NewRDFEntry(key, value)
}

func (e RDFEntry) KeyMtEntry() (*big.Int, error) {
	return e.key.MtEntry()
}

func (e RDFEntry) ValueMtEntry() (*big.Int, error) {
	return mkValueMtEntry(e.getHasher(), e.value)
}

func (e RDFEntry) KeyValueMtEntries() (
	keyMtEntry *big.Int, valueMtEntry *big.Int, err error) {

	keyMtEntry, err = e.KeyMtEntry()
	if err != nil {
		return nil, nil, err
	}

	valueMtEntry, err = e.ValueMtEntry()
	if err != nil {
		return nil, nil, err
	}

	return keyMtEntry, valueMtEntry, nil
}

func (e RDFEntry) getHasher() Hasher {
	h := e.hasher
	if h == nil {
		h = defaultHasher
	}
	return h
}
