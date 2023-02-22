package c_polygonid

import (
	"encoding/hex"
	"errors"
	"log"

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
