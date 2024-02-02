package c_polygonid

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"log"
	"strconv"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-crypto/babyjub"
)

// wrapper type to unmarshal signature from json
type hexSigJson babyjub.Signature

func (s *hexSigJson) UnmarshalJSON(bytes []byte) error {
	const compSigLn = len(babyjub.SignatureComp{})
	if compSigLn*2+2 != len(bytes) {
		log.Print(len(bytes), compSigLn)
		return errors.New("invalid signature length")
	}

	if bytes[0] != '"' || bytes[len(bytes)-1] != '"' {
		return errors.New("invalid signature format")
	}

	var compSigBytes [compSigLn]byte
	ln, err := hex.Decode(compSigBytes[:], bytes[1:len(bytes)-1])
	if err != nil {
		return err
	}
	if ln != compSigLn {
		return errors.New("incorrect signature length decoded")
	}
	_, err = (*babyjub.Signature)(s).Decompress(compSigBytes)
	return err
}

type jsonByte byte

func (b *jsonByte) Byte() byte {
	return byte(*b)
}

func (b *jsonByte) UnmarshalJSON(in []byte) error {
	if len(in) == 0 {
		return errors.New("invalid byte format")
	}
	if in[0] == '"' {
		if len(in) < 3 || in[len(in)-1] != '"' {
			return errors.New("invalid byte format")
		}

		in = in[1 : len(in)-1]
		prefix := ""
		if len(in) > 2 {
			prefix = string(in[0:2])
		}
		switch prefix {
		case "0x", "0X":
			in2, err := hex.DecodeString(string(in[2:]))
			if err != nil {
				return err
			}
			if len(in2) > 1 {
				return errors.New("invalid byte format")
			}
			*b = jsonByte(in2[0])
		case "0b", "0B":
			i, err := strconv.ParseUint(string(in[2:]), 2, 8)
			if err != nil {
				return err
			}
			*b = jsonByte(i)
		}
	}
	i, err := strconv.ParseUint(string(in), 10, 8)
	if err != nil {
		return err
	}
	*b = jsonByte(i)
	return nil
}

// function to fail a compilation if underlined type is not int32
func assertUnderlineTypeInt32[T ~int32](_ T) {}

func chainIDToInt(chainID core.ChainID) int {
	// assertion is required to correctly handle the underlined type during
	// int conversion
	assertUnderlineTypeInt32(chainID)
	return int(chainID)
}

func chainIDToBytes(chainID core.ChainID) []byte {
	// assertion is required to correctly handle the underlined type during
	// int to bytes serialization
	assertUnderlineTypeInt32(chainID)
	var chainIDBytes [4]byte
	binary.LittleEndian.PutUint32(chainIDBytes[:], uint32(chainID))
	return chainIDBytes[:]
}
