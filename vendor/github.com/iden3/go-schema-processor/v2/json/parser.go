package json

import (
	"context"
	"encoding/json"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-schema-processor/v2/processor"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

const contextFullKey = "@context"

// Parser can parse claim data according to specification
type Parser struct {
}

// ParseClaim creates Claim object from W3CCredential
// Deprecated: use credential.ToCoreClaim instead
func (s Parser) ParseClaim(ctx context.Context,
	credential verifiable.W3CCredential,
	opts *processor.CoreClaimOptions) (*core.Claim, error) {
	verifiableOpts := verifiable.CoreClaimOptions(*opts)
	return credential.ToCoreClaim(ctx, &verifiableOpts)
}

// GetFieldSlotIndex return index of slot from 0 to 7 (each claim has by default 8 slots)
func (s Parser) GetFieldSlotIndex(field string, typeName string,
	schemaBytes []byte) (int, error) {

	var ctxDoc any
	err := json.Unmarshal(schemaBytes, &ctxDoc)
	if err != nil {
		return -1, err
	}

	ctxDocM, ok := ctxDoc.(map[string]any)
	if !ok {
		return -1, errors.New("document is not an object")
	}

	ctxDoc, ok = ctxDocM[contextFullKey]
	if !ok {
		return -1, errors.New("document has no @context")
	}

	ldCtx, err := ld.NewContext(nil, nil).Parse(ctxDoc)
	if err != nil {
		return -1, err
	}

	serAttr, err := verifiable.GetSerializationAttrFromParsedContext(ldCtx, typeName)
	if err != nil {
		return -1, err
	}
	if serAttr == "" {
		return -1, errors.Errorf(
			"field `%s` not specified in serialization info", field)
	}

	sPaths, err := verifiable.ParseSerializationAttr(serAttr)
	if err != nil {
		return -1, err
	}

	switch field {
	case sPaths.IndexAPath:
		return 2, nil
	case sPaths.IndexBPath:
		return 3, nil
	case sPaths.ValueAPath:
		return 6, nil
	case sPaths.ValueBPath:
		return 7, nil
	default:
		return -1, errors.Errorf(
			"field `%s` not specified in serialization info", field)
	}
}
