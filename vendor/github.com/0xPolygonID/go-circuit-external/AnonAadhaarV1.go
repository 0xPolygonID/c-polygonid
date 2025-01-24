package gocircuitexternal

import (
	"encoding/json"
	"fmt"
	"math/big"
	"reflect"
	"strconv"
	"time"

	"github.com/iden3/go-circuits/v2"
	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/merklize"
)

// we need to patch time.Now to get the same issued and expiration dates
// for unit tests
var now = time.Now().UTC()

const (
	AnonAadhaarV1 circuits.CircuitID = "anonAadhaarV1"
)

type AnonAadhaarV1Inputs struct {
	QRData *big.Int `json:"qrData"`
	// Generated on mobile app values
	CredentialSubjectID             string `json:"credentialSubjectID"`             // credentialSubject.id
	CredentialStatusRevocationNonce int    `json:"credentialStatusRevocationNonce"` // credentialStatus.revocationNonce
	CredentialStatusID              string `json:"credentialStatusID"`              // credentialStatus.id
	// Mobile dynamic values with Firebase config
	IssuerID      string `json:"issuerID"`      // issuer
	PubKey        string `json:"pubKey"`        // pubKey
	NullifierSeed int    `json:"nullifierSeed"` // nullifierSeed
	SignalHash    int    `json:"signalHash"`    // signalHash
}

type anonAadhaarV1CircuitInputs struct {
	QRDataPadded        []string   `json:"qrDataPadded"`
	QRDataPaddedLength  int        `json:"qrDataPaddedLength"`
	DelimiterIndices    []int      `json:"delimiterIndices"`
	Signature           []string   `json:"signature"`
	PubKey              []string   `json:"pubKey"`
	NullifierSeed       int        `json:"nullifierSeed"`
	SignalHash          int        `json:"signalHash"`
	RevocationNonce     int        `json:"revocationNonce"`
	CredentialStatusID  string     `json:"credentialStatusID"`
	CredentialSubjectID string     `json:"credentialSubjectID"`
	UserID              string     `json:"userID"`
	ExpirationDate      string     `json:"expirationDate"`
	IssuanceDate        string     `json:"issuanceDate"`
	Issuer              string     `json:"issuer"`
	TemplateRoot        string     `json:"templateRoot"`
	Siblings            [][]string `json:"siblings"`
}

func (a *AnonAadhaarV1Inputs) InputsMarshal() ([]byte, error) {
	mt, err := newTemplateTree()
	if err != nil {
		return nil, fmt.Errorf("failed to create template tree: %w", err)
	}
	templateRoot := mt.root()

	p, err := extractNfromPubKey([]byte(a.PubKey))
	if err != nil {
		return nil, fmt.Errorf("failed to extract pubkey: %w", err)
	}
	pk, err := splitToWords(p, big.NewInt(121), big.NewInt(17))
	if err != nil {
		return nil, fmt.Errorf("failed to split pubkey: %w", err)
	}

	qrParser, err := newQRParser(a.QRData)
	if err != nil {
		return nil, fmt.Errorf("failed to create QR parser: %w", err)
	}
	dataPadded, dataPaddedLen, delimiterIndices, sig, err := qrParser.payload()
	if err != nil {
		return nil, fmt.Errorf("failed to extract payload from QR: %w", err)
	}
	qrFields, err := qrParser.fields()
	if err != nil {
		return nil, fmt.Errorf("failed to extract QR fields: %w", err)
	}
	signature, err := splitToWords(sig, big.NewInt(121), big.NewInt(17))
	if err != nil {
		return nil, fmt.Errorf("failed to split signature: %w", err)
	}

	credentialStatusID, err := hashvalue(a.CredentialStatusID)
	if err != nil {
		return nil, fmt.Errorf("failed to hash credentialStatusID: %w", err)
	}
	credentialSubjetID, err := hashvalue(a.CredentialSubjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to hash credentialSubjectID for credential: %w", err)
	}
	userDID, err := w3c.ParseDID(a.CredentialSubjectID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credentialSubjectID for claim: %w", err)
	}
	userID, err := core.IDFromDID(*userDID)
	if err != nil {
		return nil, fmt.Errorf("failed to get userID: %w", err)
	}

	currentTime := time.Now().UTC()
	issuanceDate, err := hashvalue(currentTime)
	if err != nil {
		return nil, fmt.Errorf("failed to hash issuanceDate: %w", err)
	}

	expirationDate := currentTime.AddDate(0, 6, 0)
	// we need this check to ensure
	// that we can reproduce the same expiration date in the circuit.
	// Since the circuit recovers the expiration date nanoseconds from the timestamp in unix
	if err = isTimeUnderPrime(expirationDate); err != nil {
		return nil, fmt.Errorf(
			"expiration date '%s' out of prime: %w", expirationDate, err)
	}

	// convert timestamp to nanoseconds (Unix time)
	// ensure expirationDate field in the verifiable credential ends in zeros,
	// representing nanoseconds, e.g., 2025-12-23T20:53:09.000000000Z
	expirationDateUnix := big.NewInt(expirationDate.Unix())
	expirationDateUnixNano := new(big.Int).Mul(expirationDateUnix, big.NewInt(1_000_000_000))

	issuer, err := hashvalue(a.IssuerID)
	if err != nil {
		return nil, fmt.Errorf("failed to hash issuer: %w", err)
	}

	proofs, err := mt.update(updateValues{
		Birthday:            qrFields.Birthday,
		Gender:              qrFields.Gender,
		Pincode:             qrFields.Pincode,
		State:               qrFields.State,
		RevocationNonce:     big.NewInt(int64(a.CredentialStatusRevocationNonce)),
		CredentialStatusID:  credentialStatusID,
		CredentialSubjectID: credentialSubjetID,
		ExpirationDate:      expirationDateUnixNano,
		IssuanceDate:        issuanceDate,
		Issuer:              issuer,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to update template tree: %w", err)
	}

	updateSyblings := make([][]string, 0, len(proofs))
	for _, p := range proofs {
		// golnag library generates one extra sibling
		// that is not needed for the circuit
		// the last sibling should be 0 all the time
		if p.Siblings[len(p.Siblings)-1].BigInt().Cmp(big.NewInt(0)) != 0 {
			return nil, fmt.Errorf("last sibling should be 0")
		}
		updateSyblings = append(updateSyblings, circuits.PrepareSiblingsStr(p.Siblings[:treeLevel], treeLevel))
	}

	inputs := anonAadhaarV1CircuitInputs{
		QRDataPadded:        uint8ArrayToCharArray(dataPadded),
		QRDataPaddedLength:  dataPaddedLen,
		DelimiterIndices:    delimiterIndices,
		Signature:           toString(signature),
		PubKey:              toString(pk),
		NullifierSeed:       a.NullifierSeed,
		SignalHash:          a.SignalHash,
		RevocationNonce:     a.CredentialStatusRevocationNonce,
		CredentialStatusID:  credentialStatusID.String(),
		CredentialSubjectID: credentialSubjetID.String(),
		UserID:              userID.BigInt().String(),
		ExpirationDate:      expirationDateUnix.String(),
		IssuanceDate:        issuanceDate.String(),
		Issuer:              issuer.String(),
		TemplateRoot:        templateRoot.String(),
		Siblings:            updateSyblings,
	}

	jsonBytes, err := json.Marshal(inputs)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal inputs: %w", err)
	}

	return jsonBytes, nil
}

func hashvalue(v interface{}) (*big.Int, error) {
	mv, err := merklize.NewValue(merklize.PoseidonHasher{}, v)
	if err != nil {
		return nil, fmt.Errorf("failed to create init merklizer: %w", err)
	}
	bv, err := mv.MtEntry()
	if err != nil {
		return nil, fmt.Errorf("failed to create merklize entry: %w", err)
	}
	return bv, nil
}

// AnonAadhaarV1PubSignals public inputs
type AnonAadhaarV1PubSignals struct {
	PubKeyHash     string
	Nullifier      string
	ClaimRoot      string
	HashIndex      string
	HashValue      string
	NullifierSeed  int
	SignalHash     int
	ExpirationDate string
	TemplateRoot   string
}

// PubSignalsUnmarshal unmarshal credentialAtomicQueryV3.circom public signals
func (a *AnonAadhaarV1PubSignals) PubSignalsUnmarshal(data []byte) error {
	// expected order:
	// 0 - pubKeyHash
	// 1 - nullifier
	// 2 - claimRoot
	// 3 - hashIndex
	// 4 - hashValue
	// 5 - nullifierSeed
	// 6 - signalHash
	// 7 - expirationDate
	// 8 - templateRoot

	const fieldLength = 9

	var sVals []string
	err := json.Unmarshal(data, &sVals)
	if err != nil {
		return err
	}

	if len(sVals) != fieldLength {
		return fmt.Errorf("expected %d values, got %d", fieldLength, len(sVals))
	}

	a.PubKeyHash = sVals[0]
	a.Nullifier = sVals[1]
	a.ClaimRoot = sVals[2]
	a.HashIndex = sVals[3]
	a.HashValue = sVals[4]
	a.NullifierSeed, err = strconv.Atoi(sVals[5])
	if err != nil {
		return fmt.Errorf("failed to parse nullifierSeed: %w", err)
	}
	a.SignalHash, err = strconv.Atoi(sVals[6])
	if err != nil {
		return fmt.Errorf("failed to parse signalHash: %w", err)
	}
	a.ExpirationDate = sVals[7]
	a.TemplateRoot = sVals[8]

	return nil
}

// GetObjMap returns struct field as a map
func (a *AnonAadhaarV1PubSignals) GetObjMap() map[string]interface{} {
	out := make(map[string]interface{})

	value := reflect.ValueOf(a)
	if value.Kind() == reflect.Ptr {
		value = value.Elem()
	}

	typ := value.Type()
	for i := 0; i < value.NumField(); i++ {
		fi := typ.Field(i)
		if jsonTag := fi.Tag.Get("json"); jsonTag != "" {
			out[jsonTag] = value.Field(i).Interface()
		}
	}
	return out
}
