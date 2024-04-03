package c_polygonid

import (
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math/big"
	"strconv"
	"strings"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-iden3-crypto/babyjub"
	"github.com/iden3/go-iden3-crypto/utils"
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
	num := string(in)
	radix := 10
	if in[0] == '"' {
		if len(in) < 3 || in[len(in)-1] != '"' {
			return errors.New("invalid byte format")
		}

		num = string(in[1 : len(in)-1])
		prefix := ""
		if len(num) > 2 {
			prefix = num[:2]
		}
		switch prefix {
		case "0x", "0X":
			radix = 16
			num = num[2:]
		case "0b", "0B":
			radix = 2
			num = num[2:]
		}
	}
	i, err := strconv.ParseUint(num, radix, 8)
	if err != nil {
		return err
	}
	*b = jsonByte(i)
	return nil
}

type jsonNumber big.Int

// UnmarshalJSON implements json.Unmarshaler interface. It unmarshals any
// number-like JSON value into a big.Int.
//
// Examples:
//
//	"0x123" -> 291
//	"0X123" -> 291
//	  "123" -> 123
//	    123 -> 123
func (j *jsonNumber) UnmarshalJSON(in []byte) error {
	if len(in) == 0 {
		return errors.New("empty input")
	}

	if j == nil {
		return errors.New("jsonNumber is nil")
	}

	var s string
	var radix = 10

	if in[0] >= '0' && in[0] <= '9' {
		s = string(in)
	} else if in[0] == '"' && in[len(in)-1] == '"' {
		s = string(in[1 : len(in)-1])
		if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
			radix = 16
			s = s[2:]
		}
	}

	_, ok := ((*big.Int)(j)).SetString(s, radix)
	if !ok {
		return errors.New("invalid integer number format")
	}

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

type JsonFieldIntStr big.Int

func (i *JsonFieldIntStr) UnmarshalJSON(bytes []byte) error {
	var s *string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}
	if s == nil {
		(*big.Int)(i).SetInt64(0)
		return nil
	}

	_, ok := (*big.Int)(i).SetString(*s, 10)
	if !ok {
		return fmt.Errorf("invalid Int string")
	}

	if !utils.CheckBigIntInField((*big.Int)(i)) {
		return fmt.Errorf("int is not in field")
	}

	return nil
}

func (i *JsonFieldIntStr) Int() *big.Int {
	return (*big.Int)(i)
}

type coreDID w3c.DID

func (d *coreDID) UnmarshalJSON(bytes []byte) error {
	var s *string
	err := json.Unmarshal(bytes, &s)
	if err != nil {
		return err
	}
	if s == nil {
		*d = coreDID(w3c.DID{})
		return nil
	}

	did, err := w3c.ParseDID(*s)
	if err != nil {
		return err
	}

	*d = coreDID(*did)
	return nil
}
