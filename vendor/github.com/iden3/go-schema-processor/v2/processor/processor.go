package processor

import (
	"context"
	"encoding/json"

	core "github.com/iden3/go-iden3-core/v2"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/piprate/json-gold/ld"
	"github.com/pkg/errors"
)

// Processor is set of tool for claim processing
type Processor struct {
	Validator      Validator
	DocumentLoader ld.DocumentLoader
	Parser         Parser
}

// Validator is interface to validate data and documents
type Validator interface {
	ValidateData(data, schema []byte) error
}

// Parser is an interface to parse claim slots
type Parser interface {
	// Deprecated: use credential.ToCoreClaim instead
	ParseClaim(ctx context.Context, credential verifiable.W3CCredential,
		options *CoreClaimOptions) (*core.Claim, error)
	GetFieldSlotIndex(field string, typeName string, schema []byte) (int, error)
}

// CoreClaimOptions is params for core claim parsing
// Deprecated: use verifiable.CoreClaimOptions instead
type CoreClaimOptions verifiable.CoreClaimOptions

var (
	errParserNotDefined    = errors.New("parser is not defined")
	errLoaderNotDefined    = errors.New("loader is not defined")
	errValidatorNotDefined = errors.New("validator is not defined")
)

// Opt returns configuration options for processor suite
type Opt func(opts *Processor)

// WithValidator return new options
func WithValidator(s Validator) Opt {
	return func(opts *Processor) {
		opts.Validator = s
	}
}

// WithDocumentLoader return new options
func WithDocumentLoader(s ld.DocumentLoader) Opt {
	return func(opts *Processor) {
		opts.DocumentLoader = s
	}
}

// WithParser return new options
func WithParser(s Parser) Opt {
	return func(opts *Processor) {
		opts.Parser = s
	}
}

// InitProcessorOptions initializes processor with options.
func InitProcessorOptions(processor *Processor, opts ...Opt) *Processor {
	for _, opt := range opts {
		opt(processor)
	}
	return processor
}

// Load will load a schema by given url.
func (s *Processor) Load(ctx context.Context, url string) (schema []byte, err error) {
	if s.DocumentLoader == nil {
		return nil, errLoaderNotDefined
	}
	doc, err := s.DocumentLoader.LoadDocument(url)
	if err != nil {
		return nil, err
	}
	return json.Marshal(doc.Document)
}

// ParseClaim will serialize input data to index and value fields.
func (s *Processor) ParseClaim(ctx context.Context,
	credential verifiable.W3CCredential,
	opts *CoreClaimOptions) (*core.Claim, error) {

	if s.Parser == nil {
		return nil, errParserNotDefined
	}
	return s.Parser.ParseClaim(ctx, credential, opts)
}

// GetFieldSlotIndex returns index of slot for specified field according to schema
func (s *Processor) GetFieldSlotIndex(field string, typeName string,
	schema []byte) (int, error) {

	if s.Parser == nil {
		return 0, errParserNotDefined
	}
	return s.Parser.GetFieldSlotIndex(field, typeName, schema)
}

// ValidateData will validate a claim content by given schema.
func (s *Processor) ValidateData(data, schema []byte) error {
	if s.Validator == nil {
		return errValidatorNotDefined
	}
	return s.Validator.ValidateData(data, schema)
}
