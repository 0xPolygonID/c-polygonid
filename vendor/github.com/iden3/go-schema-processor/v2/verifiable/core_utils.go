package verifiable

import (
	"fmt"
	"strings"

	"github.com/iden3/go-schema-processor/v2/merklize"
	"github.com/iden3/go-schema-processor/v2/utils"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

const (
	credentialSubjectKey = "credentialSubject"
	//nolint:gosec // G101: this is not a hardcoded credential
	credentialSubjectFullKey = "https://www.w3.org/2018/credentials#credentialSubject"
	//nolint:gosec // G101: this is not a hardcoded credential
	verifiableCredentialFullKey = "https://www.w3.org/2018/credentials#VerifiableCredential"
	typeFullKey                 = "@type"
	contextFullKey              = "@context"
	serializationFullKey        = "iden3_serialization"
)

// CoreClaimOptions is params for core claim parsing
type CoreClaimOptions struct {
	RevNonce              uint64 `json:"revNonce"`
	Version               uint32 `json:"version"`
	SubjectPosition       string `json:"subjectPosition"`
	MerklizedRootPosition string `json:"merklizedRootPosition"`
	Updatable             bool   `json:"updatable"`
	MerklizerOpts         []merklize.MerklizeOption
}

func findCredentialType(mz *merklize.Merklizer) (string, error) {
	opts := mz.Options()

	// try to look into credentialSubject.@type to get type of credentials
	path1, err := opts.NewPath(credentialSubjectFullKey, typeFullKey)
	if err == nil {
		var e any
		e, err = mz.RawValue(path1)
		if err == nil {
			tp, ok := e.(string)
			if ok {
				return tp, nil
			}
		}
	}

	// if type of credentials not found in credentialSubject.@type, loop at
	// top level @types if it contains two elements: type we are looking for
	// and "VerifiableCredential" type.
	path2, err := opts.NewPath(typeFullKey)
	if err != nil {
		return "", err
	}

	e, err := mz.RawValue(path2)
	if err != nil {
		return "", err
	}

	eArr, ok := e.([]any)
	if !ok {
		return "", fmt.Errorf("top level @type expected to be an array")
	}
	topLevelTypes, err := toStringSlice(eArr)
	if err != nil {
		return "", err
	}
	if len(topLevelTypes) != 2 {
		return "", fmt.Errorf("top level @type expected to be of length 2")
	}

	switch verifiableCredentialFullKey {
	case topLevelTypes[0]:
		return topLevelTypes[1], nil
	case topLevelTypes[1]:
		return topLevelTypes[0], nil
	default:
		return "", fmt.Errorf(
			"@type(s) are expected to contain VerifiableCredential type")
	}
}

func toStringSlice(in []any) ([]string, error) {
	out := make([]string, len(in))
	for i, v := range in {
		s, ok := v.(string)
		if !ok {
			return nil, fmt.Errorf("element #%v is not a string", i)
		}
		out[i] = s
	}
	return out, nil
}

// parsedSlots is struct that represents iden3 claim specification
type parsedSlots struct {
	IndexA, IndexB []byte
	ValueA, ValueB []byte
}

// parseSlots converts payload to claim slots using provided schema
func parseSlots(mz *merklize.Merklizer,
	credential W3CCredential,
	credentialType string) (parsedSlots, bool, error) {

	slots := parsedSlots{
		IndexA: make([]byte, 32),
		IndexB: make([]byte, 32),
		ValueA: make([]byte, 32),
		ValueB: make([]byte, 32),
	}

	jsonLDOpts := mz.Options().JSONLDOptions()
	serAttr, err := getSerializationAttr(credential, jsonLDOpts,
		credentialType)
	if err != nil {
		return slots, false, err
	}

	if serAttr == "" {
		return slots, false, nil
	}

	sPaths, err := ParseSerializationAttr(serAttr)
	if err != nil {
		return slots, true, err
	}

	if sPaths.isEmpty() {
		return slots, true, nil
	}

	err = fillSlot(slots.IndexA, mz, sPaths.IndexAPath)
	if err != nil {
		return slots, true, err
	}
	err = fillSlot(slots.IndexB, mz, sPaths.IndexBPath)
	if err != nil {
		return slots, true, err
	}
	err = fillSlot(slots.ValueA, mz, sPaths.ValueAPath)
	if err != nil {
		return slots, true, err
	}
	err = fillSlot(slots.ValueB, mz, sPaths.ValueBPath)
	if err != nil {
		return slots, true, err
	}

	return slots, true, nil
}

// Get `iden3_serialization` attr definition from context document either using
// type name like DeliverAddressMultiTestForked or by type id like
// urn:uuid:ac2ede19-b3b9-454d-b1a9-a7b3d5763100.
func getSerializationAttr(credential W3CCredential,
	opts *ld.JsonLdOptions, tp string) (string, error) {

	ldCtx, err := ld.NewContext(nil, opts).Parse(anySlice(credential.Context))
	if err != nil {
		return "", err
	}

	return GetSerializationAttrFromParsedContext(ldCtx, tp)
}

// convert from the slice of concrete type to the slice of interface{}
func anySlice[T any](in []T) []any {
	if in == nil {
		return nil
	}
	s := make([]any, len(in))
	for i := range in {
		s[i] = in[i]
	}
	return s
}

func GetSerializationAttrFromParsedContext(ldCtx *ld.Context,
	tp string) (string, error) {

	termDef, ok := ldCtx.AsMap()["termDefinitions"]
	if !ok {
		return "", errors.New("types now found in context")
	}

	termDefM, ok := termDef.(map[string]any)
	if !ok {
		return "", errors.New("terms definitions is not of correct type")
	}

	for typeName, typeDef := range termDefM {
		typeDefM, ok := typeDef.(map[string]any)
		if !ok {
			// not a type
			continue
		}
		typeCtx, ok := typeDefM[contextFullKey]
		if !ok {
			// not a type
			continue
		}
		typeCtxM, ok := typeCtx.(map[string]any)
		if !ok {
			return "", errors.New("type @context is not of correct type")
		}
		typeID, _ := typeDefM["@id"].(string)
		if typeName != tp && typeID != tp {
			continue
		}

		serStr, _ := typeCtxM[serializationFullKey].(string)
		return serStr, nil
	}

	return "", nil
}

type slotsPaths struct {
	IndexAPath string
	IndexBPath string
	ValueAPath string
	ValueBPath string
}

func ParseSerializationAttr(serAttr string) (slotsPaths, error) {
	prefix := "iden3:v1:"
	if !strings.HasPrefix(serAttr, prefix) {
		return slotsPaths{},
			errors.New("serialization attribute does not have correct prefix")
	}
	parts := strings.Split(serAttr[len(prefix):], "&")
	if len(parts) > 4 {
		return slotsPaths{},
			errors.New("serialization attribute has too many parts")
	}
	var paths slotsPaths
	for _, part := range parts {
		kv := strings.Split(part, "=")
		if len(kv) != 2 {
			return slotsPaths{}, errors.New(
				"serialization attribute part does not have correct format")
		}
		switch kv[0] {
		case "slotIndexA":
			paths.IndexAPath = kv[1]
		case "slotIndexB":
			paths.IndexBPath = kv[1]
		case "slotValueA":
			paths.ValueAPath = kv[1]
		case "slotValueB":
			paths.ValueBPath = kv[1]
		default:
			return slotsPaths{},
				errors.New("unknown serialization attribute slot")
		}
	}
	return paths, nil
}

func (p slotsPaths) isEmpty() bool {
	return p.IndexAPath == "" && p.IndexBPath == "" &&
		p.ValueAPath == "" && p.ValueBPath == ""
}

func fillSlot(slotData []byte, mz *merklize.Merklizer, path string) error {
	if path == "" {
		return nil
	}

	path = credentialSubjectKey + "." + path
	p, err := mz.ResolveDocPath(path)
	if err != nil {
		return errors.Wrapf(err, "field not found in credential %s", path)
	}

	entry, err := mz.Entry(p)
	if errors.Is(err, merklize.ErrorEntryNotFound) {
		return errors.Wrapf(err, "field not found in credential %s", path)
	} else if err != nil {
		return err
	}

	intVal, err := entry.ValueMtEntry()
	if err != nil {
		return err
	}

	bytesVal := utils.SwapEndianness(intVal.Bytes())
	copy(slotData, bytesVal)
	return nil
}
