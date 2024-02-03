package c_polygonid

import (
	"encoding/json"
	"errors"
	"hash/fnv"
	"math"
	"math/big"

	core "github.com/iden3/go-iden3-core/v2"
)

type MethodConfig struct {
	MethodName  core.DIDMethod  `json:"name"`
	Blockchain  core.Blockchain `json:"blockchain"`
	NetworkID   core.NetworkID  `json:"network"`
	NetworkFlag byte            `json:"networkFlag"`
	MethodByte  byte            `json:"methodByte"`
	ChainID     core.ChainID    `json:"chainId"`
}

func (cfg *MethodConfig) UnmarshalJSON(in []byte) error {
	var j struct {
		MethodName  *core.DIDMethod  `json:"name"`
		Blockchain  *core.Blockchain `json:"blockchain"`
		NetworkID   *core.NetworkID  `json:"network"`
		NetworkFlag *jsonByte        `json:"networkFlag"`
		MethodByte  *jsonByte        `json:"methodByte"`
		ChainID     *jsonNumber      `json:"chainId"`
	}
	err := json.Unmarshal(in, &j)
	if err != nil {
		return err
	}

	if j.MethodName == nil {
		return errors.New("method name is empty")
	}
	cfg.MethodName = *j.MethodName

	if j.Blockchain == nil {
		return errors.New("blockchain is empty")
	}
	cfg.Blockchain = *j.Blockchain

	if j.NetworkID == nil {
		return errors.New("network ID is empty")
	}
	cfg.NetworkID = *j.NetworkID

	if j.NetworkFlag == nil {
		return errors.New("network flag is not set")
	}
	cfg.NetworkFlag = byte(*j.NetworkFlag)

	if j.MethodByte == nil {
		return errors.New("method byte is not set")
	}
	cfg.MethodByte = byte(*j.MethodByte)

	if j.ChainID == nil {
		return errors.New("chain ID is not set")
	}
	assertUnderlineTypeInt32(cfg.ChainID)
	chainID := (*big.Int)(j.ChainID)
	if !chainID.IsInt64() {
		return errors.New("chain ID is not inside int32 bounds")
	}
	chainIDi := chainID.Int64()
	if chainIDi > math.MaxInt32 || chainIDi < math.MinInt32 {
		return errors.New("chain ID is not inside int32 bounds")
	}
	cfg.ChainID = core.ChainID(chainIDi)

	return nil
}

// Hash generate a unique hash for the method config
func (cfg MethodConfig) Hash() uint64 {
	h := fnv.New64a()
	// errors are always nil
	_, _ = h.Write([]byte(cfg.MethodName))
	_, _ = h.Write([]byte(cfg.Blockchain))
	_, _ = h.Write([]byte(cfg.NetworkID))
	_, _ = h.Write([]byte{cfg.NetworkFlag, cfg.MethodByte})
	_, _ = h.Write(chainIDToBytes(cfg.ChainID))
	return h.Sum64()
}
