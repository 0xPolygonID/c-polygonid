package c_polygonid

import (
	"encoding/json"
	"errors"
	"math/big"
)

type JsonBigInt big.Int

func (j *JsonBigInt) UnmarshalJSON(bytes []byte) error {
	var s string
	if err := json.Unmarshal(bytes, &s); err != nil {
		return err
	}
	var i = (*big.Int)(j)
	_, ok := i.SetString(s, 10)
	if !ok {
		return errors.New("error parsing big.Int")
	}
	return nil
}

func (j *JsonBigInt) BigInt() *big.Int {
	return (*big.Int)(j)
}
