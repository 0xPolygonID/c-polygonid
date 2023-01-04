package c_polygonid

import (
	"encoding/json"
	"math/big"

	"github.com/iden3/go-merkletree-sql/v2"
)

func ProofFromSmartContract(
	scProof SmartContractProof) (*merkletree.Proof, *merkletree.Hash, error) {

	var nodeAux *merkletree.NodeAux
	var err error

	if scProof.AuxExistence {
		nodeAux = &merkletree.NodeAux{}
		nodeAux.Key, err = merkletree.NewHashFromBigInt(scProof.AuxIndex)
		if err != nil {
			return &merkletree.Proof{}, &merkletree.Hash{}, err
		}
		nodeAux.Value, err = merkletree.NewHashFromBigInt(scProof.AuxValue)
		if err != nil {
			return &merkletree.Proof{}, &merkletree.Hash{}, err
		}
	}

	allSiblings := make([]*merkletree.Hash, len(scProof.Siblings))
	for i, s := range scProof.Siblings {
		allSiblings[i], err = merkletree.NewHashFromBigInt(s)
		if err != nil {
			return &merkletree.Proof{}, &merkletree.Hash{}, err
		}
	}

	proof, err := merkletree.NewProofFromData(scProof.Existence, allSiblings,
		nodeAux)
	if err != nil {
		return &merkletree.Proof{}, &merkletree.Hash{}, err
	}

	root, err := merkletree.NewHashFromBigInt(scProof.Root)
	if err != nil {
		return &merkletree.Proof{}, &merkletree.Hash{}, err
	}

	return proof, root, nil
}

type SmartContractProof struct {
	Root         *big.Int
	Existence    bool
	Siblings     []*big.Int
	AuxExistence bool
	AuxIndex     *big.Int
	AuxValue     *big.Int
}

func (s *SmartContractProof) UnmarshalJSON(bytes []byte) error {
	var j struct {
		Root         JsonBigInt     `json:"root"`
		Existence    bool           `json:"existence"`
		Siblings     [32]JsonBigInt `json:"siblings"`
		AuxExistence bool           `json:"auxExistence"`
		AuxIndex     JsonBigInt     `json:"auxIndex"`
		AuxValue     JsonBigInt     `json:"auxValue"`
	}

	if err := json.Unmarshal(bytes, &j); err != nil {
		return err
	}
	s.Root = j.Root.BigInt()
	s.Existence = j.Existence
	s.Siblings = make([]*big.Int, len(j.Siblings))
	for i := range j.Siblings {
		s.Siblings[i] = j.Siblings[i].BigInt()
	}
	s.AuxExistence = j.AuxExistence
	s.AuxIndex = j.AuxIndex.BigInt()
	s.AuxValue = j.AuxValue.BigInt()
	return nil
}
