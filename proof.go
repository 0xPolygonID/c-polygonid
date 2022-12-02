package c_polygonid

import (
	"encoding/json"
	"errors"
	"math/big"

	"github.com/iden3/go-merkletree-sql/v2"
)

type SmartContractProof struct {
	Root     *big.Int
	Siblings []*big.Int
	OldKey   *big.Int
	OldValue *big.Int
	IsOld0   bool
	Fnc      *big.Int
}

func (s *SmartContractProof) UnmarshalJSON(bytes []byte) error {
	var j smartContractProofJson
	if err := json.Unmarshal(bytes, &j); err != nil {
		return err
	}
	s.Root = j.Root.BigInt()
	s.Siblings = make([]*big.Int, len(j.Siblings))
	for i := range j.Siblings {
		s.Siblings[i] = j.Siblings[i].BigInt()
	}
	s.OldKey = j.OldKey.BigInt()
	s.OldValue = j.OldValue.BigInt()
	s.IsOld0 = j.IsOld0
	s.Fnc = j.Fnc.BigInt()
	return nil
}

type smartContractProofJson struct {
	Root     jsonInt
	Siblings [32]jsonInt
	OldKey   jsonInt
	OldValue jsonInt
	IsOld0   bool
	Fnc      jsonInt
}

type jsonInt big.Int

func (j *jsonInt) UnmarshalJSON(bytes []byte) error {
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

func (j *jsonInt) MarshalJSON() ([]byte, error) {
	if j == nil {
		return []byte("null"), nil
	}

	return json.Marshal((*big.Int)(j).String())
}

func (j *jsonInt) BigInt() *big.Int {
	return (*big.Int)(j)
}

func ProofFromSmartContract(
	scProof SmartContractProof) (*merkletree.Proof, *merkletree.Hash, error) {

	var existence bool
	var nodeAux *merkletree.NodeAux
	var err error

	if scProof.Fnc.Cmp(big.NewInt(0)) == 0 {
		existence = true
	} else {
		existence = false

		if !scProof.IsOld0 {
			nodeAux = &merkletree.NodeAux{}
			nodeAux.Key, err = merkletree.NewHashFromBigInt(scProof.OldKey)
			if err != nil {
				return &merkletree.Proof{}, &merkletree.Hash{}, err
			}
			nodeAux.Value, err = merkletree.NewHashFromBigInt(scProof.OldValue)
			if err != nil {
				return &merkletree.Proof{}, &merkletree.Hash{}, err
			}
		}
	}

	allSiblings := make([]*merkletree.Hash, len(scProof.Siblings))
	for i, s := range scProof.Siblings {
		allSiblings[i], err = merkletree.NewHashFromBigInt(s)
		if err != nil {
			return &merkletree.Proof{}, &merkletree.Hash{}, err
		}
	}

	proof, err := merkletree.NewProofFromData(existence, allSiblings, nodeAux)
	if err != nil {
		return &merkletree.Proof{}, &merkletree.Hash{}, err
	}

	root, err := merkletree.NewHashFromBigInt(scProof.Root)
	if err != nil {
		return &merkletree.Proof{}, &merkletree.Hash{}, err
	}

	return proof, root, nil
}
