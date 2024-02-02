package c_polygonid

import (
	"errors"
	"hash/fnv"

	core "github.com/iden3/go-iden3-core/v2"
)

type MethodConfig struct {
	MethodName  core.DIDMethod  `json:"name"`
	Blockchain  core.Blockchain `json:"blockchain"`
	NetworkID   core.NetworkID  `json:"network"`
	NetworkFlag *jsonByte       `json:"networkFlag"`
	MethodByte  *jsonByte       `json:"methodByte"`
	ChainID     *core.ChainID   `json:"chainId"`
}

// Hash generate a unique hash for the method config
func (cfg MethodConfig) Hash() uint64 {
	h := fnv.New64a()
	// errors are always nil
	_, _ = h.Write([]byte(cfg.MethodName))
	_, _ = h.Write([]byte(cfg.Blockchain))
	_, _ = h.Write([]byte(cfg.NetworkID))
	if cfg.NetworkFlag != nil {
		_, _ = h.Write([]byte{cfg.NetworkFlag.Byte()})
	}
	if cfg.MethodByte != nil {
		_, _ = h.Write([]byte{cfg.MethodByte.Byte()})
	}
	if cfg.ChainID != nil {
		_, _ = h.Write(chainIDToBytes(*cfg.ChainID))
	}
	return h.Sum64()
}

// Generate a unique hash for the method config
func (cfg MethodConfig) validate() error {
	if cfg.MethodName == "" {
		return errors.New("method name is empty")
	}
	if cfg.Blockchain == "" {
		return errors.New("blockchain is empty")
	}
	if cfg.NetworkID == "" {
		return errors.New("network ID is empty")
	}
	if cfg.NetworkFlag == nil {
		return errors.New("network flag is not set")
	}
	if cfg.MethodByte == nil {
		return errors.New("method byte is not set")
	}
	if cfg.ChainID == nil {
		return errors.New("chain ID is not set")
	}
	return nil
}
