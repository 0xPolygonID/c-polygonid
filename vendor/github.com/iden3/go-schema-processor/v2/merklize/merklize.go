package merklize

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/iden3/go-iden3-crypto/constants"
	"github.com/iden3/go-iden3-crypto/poseidon"
	"github.com/iden3/go-merkletree-sql/v2"
	"github.com/iden3/go-merkletree-sql/v2/db/memory"
	"github.com/iden3/go-schema-processor/v2/loaders"
	"github.com/piprate/json-gold/ld"
)

var (
	defaultHasher         Hasher = PoseidonHasher{}
	defaultDocumentLoader        = loaders.NewDocumentLoader(nil, "")
	numRE                        = regexp.MustCompile(`^\d+$`)
)

var (
	// ErrorFieldIsEmpty is returned when field path to resolve is empty
	ErrorFieldIsEmpty = errors.New("fieldPath is empty")
	// ErrorContextTypeIsEmpty is returned when context type tp resolve is empty
	ErrorContextTypeIsEmpty = errors.New("ctxType is empty")
	// ErrorUnsupportedType is returned when type is not supported
	ErrorUnsupportedType = errors.New("unsupported type")
	// ErrorEntryNotFound is returned when entry not found in merklized document
	ErrorEntryNotFound = errors.New("entry not found")
)

// SetHasher changes default hasher
func SetHasher(h Hasher) {
	if h == nil {
		panic("hasher is nil")
	}
	defaultHasher = h
}

// SetDocumentLoader changes default DocumentLoader
func SetDocumentLoader(docLoader ld.DocumentLoader) {
	defaultDocumentLoader = docLoader
}

// Options type allows to change hashing algorithm and create Path and RDFEntry
// instances with hasher different from default one.
type Options struct {
	Hasher         Hasher
	DocumentLoader ld.DocumentLoader
}

func (o Options) getHasher() Hasher {
	if o.Hasher != nil {
		return o.Hasher
	}
	return defaultHasher
}

func (o Options) getDocumentLoader() ld.DocumentLoader {
	if o.DocumentLoader != nil {
		return o.DocumentLoader
	}
	return defaultDocumentLoader
}

func (o Options) JSONLDOptions() *ld.JsonLdOptions {
	return newJSONLDOptions(true, o.getDocumentLoader())
}

func (o Options) NewPath(parts ...interface{}) (Path, error) {
	p := Path{hasher: o.getHasher()}
	err := p.Append(parts...)
	return p, err
}

func (o Options) PathFromContext(ctxBytes []byte, path string) (Path, error) {
	out := Path{hasher: o.getHasher()}
	err := out.pathFromContext(ctxBytes, path, o.JSONLDOptions())
	return out, err
}

func (o Options) FieldPathFromContext(ctxBytes []byte, ctxType, fieldPath string) (Path, error) {
	if ctxType == "" {
		return Path{}, ErrorContextTypeIsEmpty
	}
	if fieldPath == "" {
		return Path{}, ErrorFieldIsEmpty
	}

	fullPath, err := o.PathFromContext(ctxBytes, fmt.Sprintf("%s.%s", ctxType, fieldPath))
	if err != nil {
		return Path{}, err
	}

	typePath, err := o.PathFromContext(ctxBytes, ctxType)
	if err != nil {
		return Path{}, err
	}

	resPath := Path{parts: fullPath.parts[len(typePath.parts):], hasher: o.getHasher()}

	return resPath, nil
}

func (o Options) NewRDFEntry(key Path, value interface{}) (RDFEntry, error) {
	e := RDFEntry{
		key:    key,
		hasher: o.getHasher(),
	}
	if len(key.parts) == 0 {
		return e, errors.New("key length is zero")
	}

	switch v := value.(type) {
	case int:
		e.value = int64(v)
	case int64, string, bool, time.Time:
		e.value = value
	case *big.Int:
		e.value = new(big.Int).Set(v)
	default:
		return e, fmt.Errorf("incorrect value type: %T", value)
	}

	return e, nil
}

func (o Options) NewPathFromDocument(docBytes []byte,
	path string) (Path, error) {

	var docObj map[string]interface{}
	err := json.Unmarshal(docBytes, &docObj)
	if err != nil {
		return Path{}, err
	}

	pathParts := strings.Split(path, ".")
	if len(pathParts) == 0 {
		return Path{}, errors.New("path is empty")
	}

	pathPartsI, err := o.pathFromDocument(nil, docObj, pathParts, false)
	if err != nil {
		return Path{}, err
	}

	return Path{parts: pathPartsI, hasher: o.getHasher()}, nil
}

type Path struct {
	parts  []interface{} // string or int types
	hasher Hasher
}

func (p *Path) reverse() {
	for i, j := 0, len(p.parts)-1; i < j; i, j = i+1, j-1 {
		p.parts[i], p.parts[j] = p.parts[j], p.parts[i]
	}
}

func (p *Path) Parts() []interface{} {
	return p.parts
}

func NewPath(parts ...interface{}) (Path, error) {
	p := Path{hasher: defaultHasher}
	err := p.Append(parts...)
	return p, err
}

// NewPathFromContext parses context and do its best to generate full Path
// from shortcut line field1.field2.field3...
func NewPathFromContext(ctxBytes []byte, path string) (Path, error) {
	return Options{}.PathFromContext(ctxBytes, path)
}

func NewPathFromDocument(docBytes []byte, path string) (Path, error) {
	return Options{}.NewPathFromDocument(docBytes, path)
}

// NewFieldPathFromContext resolves field path without type path prefix
func NewFieldPathFromContext(ctxBytes []byte, ctxType, fieldPath string) (Path, error) {
	return Options{}.FieldPathFromContext(ctxBytes, ctxType, fieldPath)
}

// TypeIDFromContext returns @id attribute for type from JSON-LD context
func (o Options) TypeIDFromContext(ctxBytes []byte,
	typeName string) (string, error) {

	var ctxObj map[string]interface{}
	err := json.Unmarshal(ctxBytes, &ctxObj)
	if err != nil {
		return "", err
	}

	ldCtx, err := ld.NewContext(nil, o.JSONLDOptions()).
		Parse(ctxObj["@context"])
	if err != nil {
		return "", err
	}

	typeDef := ldCtx.GetTermDefinition(typeName)

	_, isType := typeDef["@context"]
	if !isType {
		return "", fmt.Errorf("looks like %v is not a type", typeName)
	}

	typeID, idFound := typeDef["@id"]
	if !idFound {
		return "", fmt.Errorf("@id attribute is not found for type %v",
			typeName)
	}

	typeIDStr, ok := typeID.(string)
	if !ok {
		return "", fmt.Errorf("@id attribute is not a string for type %v",
			typeName)
	}

	return typeIDStr, nil
}

// TypeIDFromContext returns @id attribute for type from JSON-LD context
func TypeIDFromContext(ctxBytes []byte, typeName string) (string, error) {
	return Options{}.TypeIDFromContext(ctxBytes, typeName)
}

// TypeFromContext returns type of field from context by path.
func (o Options) TypeFromContext(ctxBytes []byte, path string) (string, error) {
	var ctxObj map[string]interface{}
	err := json.Unmarshal(ctxBytes, &ctxObj)
	if err != nil {
		return "", err
	}

	ldCtx, err := ld.NewContext(nil, o.JSONLDOptions()).
		Parse(ctxObj["@context"])
	if err != nil {
		return "", err
	}

	parts := strings.Split(path, ".")

	for _, term := range parts {
		if ldCtx == nil {
			return "", errors.New("context is nil")
		}

		m := ldCtx.GetTermDefinition(term)
		_, ok := m["@id"]
		if !ok {
			return "", fmt.Errorf("no @id attribute for term: %v", term)
		}

		nextCtx, ok := m["@context"]
		if ok {
			ldCtx, err = ldCtx.Parse(nextCtx)
			if err != nil {
				return "", nil
			}
		}
	}
	return ldCtx.GetTypeMapping(parts[len(parts)-1]), nil
}

// TypeFromContext returns type of field from context by path.
func TypeFromContext(ctxBytes []byte, path string) (string, error) {
	return Options{}.TypeFromContext(ctxBytes, path)
}

func (p *Path) pathFromContext(ctxBytes []byte, path string,
	jsonLdOptions *ld.JsonLdOptions) error {

	var ctxObj map[string]interface{}
	err := json.Unmarshal(ctxBytes, &ctxObj)
	if err != nil {
		return err
	}

	ldCtx, err := ld.NewContext(nil, jsonLdOptions).Parse(ctxObj["@context"])
	if err != nil {
		return err
	}

	parts := strings.Split(path, ".")

	for _, term := range parts {
		if numRE.MatchString(term) {
			i64, err := strconv.ParseInt(term, 10, 32)
			if err != nil {
				return err
			}
			p.parts = append(p.parts, int(i64))
			continue
		}

		if ldCtx == nil {
			return errors.New("context is nil")
		}

		m := ldCtx.GetTermDefinition(term)
		id, ok := m["@id"]
		if !ok {
			return fmt.Errorf("no @id attribute for term: %v", term)
		}

		nextCtx, ok := m["@context"]
		if ok {
			var err error
			ldCtx, err = ldCtx.Parse(nextCtx)
			if err != nil {
				return err
			}
		}

		p.parts = append(p.parts, id)
	}

	return nil
}

// Create path JSON-LD document.
// If acceptArray is true, the previous element was index, and we accept an
// array
func (o Options) pathFromDocument(ldCtx *ld.Context, docObj interface{},
	pathParts []string, acceptArray bool) ([]interface{}, error) {

	if len(pathParts) == 0 {
		return nil, nil
	}

	term := pathParts[0]
	newPathParts := pathParts[1:]

	if numRE.MatchString(term) {
		i64, err := strconv.ParseInt(term, 10, 32)
		if err != nil {
			return nil, err
		}

		moreParts, err := o.pathFromDocument(ldCtx, docObj, newPathParts, true)
		if err != nil {
			return nil, err
		}

		return append([]interface{}{int(i64)}, moreParts...), nil
	}

	var docObjMap map[string]interface{}

	switch docObjT := docObj.(type) {
	case []interface{}:
		if len(docObjT) == 0 {
			return nil, errors.New("can't generate path on zero-sized array")
		}

		if !acceptArray {
			return nil, errors.New("unexpected array element")
		}

		return o.pathFromDocument(ldCtx, docObjT[0], pathParts, false)
	case map[string]interface{}:
		// pass
		docObjMap = docObjT
	default:
		return nil, fmt.Errorf("expect array or object type, got: %T", docObj)
	}

	if ldCtx == nil {
		ldCtx = ld.NewContext(nil, o.JSONLDOptions())
	}

	var err error
	ctxData, haveCtx := docObjMap["@context"]
	if haveCtx {
		ldCtx, err = ldCtx.Parse(ctxData)
		if err != nil {
			return nil, err
		}
	}

	elemOrderedKeys := ld.GetOrderedKeys(docObjMap)
	typeScopedContext := ldCtx
	for _, key := range elemOrderedKeys {
		var expandedProperty string
		expandedProperty, err = ldCtx.ExpandIri(key, false, true, nil, nil)
		if err != nil {
			return nil, err
		}

		if expandedProperty != "@type" {
			continue
		}

		types := make([]string, 0)
		switch v := docObjMap[key].(type) {
		case []interface{}:
			for _, t := range v {
				if typeStr, isString := t.(string); isString {
					types = append(types, typeStr)
				} else {
					return nil, fmt.Errorf(
						"@type value must be an array of strings: %T", t)
				}
			}
			sort.Strings(types)
		case string:
			types = append(types, v)
		default:
			return nil, fmt.Errorf("unexpected @type field type: %T",
				docObjMap[key])
		}

		for _, tt := range types {
			td := typeScopedContext.GetTermDefinition(tt)
			if ctxObj, hasCtx := td["@context"]; hasCtx {
				ldCtx, err = ldCtx.Parse(ctxObj)
				if err != nil {
					return nil, err
				}
			}
		}
		break
	}

	m := ldCtx.GetTermDefinition(term)
	id, ok := m["@id"]
	if !ok {
		return nil, fmt.Errorf("no @id attribute for term: %v", term)
	}
	idStr, ok := id.(string)
	if !ok {
		return nil, fmt.Errorf("@id attr is not of type string: %T", id)
	}

	termContext, termHasCtx := m["@context"]
	if termHasCtx {
		ldCtx, err = ldCtx.Parse(termContext)
		if err != nil {
			return nil, err
		}
	}

	moreParts, err := o.pathFromDocument(ldCtx, docObjMap[term], newPathParts,
		true)
	if err != nil {
		return nil, err
	}

	prts := append([]interface{}{idStr}, moreParts...)
	return prts, nil
}

func (p *Path) MtEntry() (*big.Int, error) {
	var err error
	h := p.hasher
	if h == nil {
		h = defaultHasher
	}

	intKeyParts := make([]*big.Int, len(p.parts))
	for i := range p.parts {
		switch v := p.parts[i].(type) {
		case string:
			intKeyParts[i], err = h.HashBytes([]byte(v))
			if err != nil {
				return nil, err
			}
		case int:
			intKeyParts[i] = big.NewInt(int64(v))
		default:
			return nil, fmt.Errorf("unexpected type %T", v)
		}
	}

	return h.Hash(intKeyParts)
}

func (p *Path) Append(parts ...interface{}) error {
	for i := range parts {
		switch parts[i].(type) {
		case string, int:
		default:
			return fmt.Errorf("incorrect part type: %T", parts)
		}
	}

	p.parts = append(p.parts, parts...)
	return nil
}

// Prepend path's parts from the beginning
func (p *Path) Prepend(parts ...interface{}) error {
	for i := range parts {
		switch parts[i].(type) {
		case string, int:
		default:
			return fmt.Errorf("incorrect part type: %T", parts)
		}
	}

	p.parts = append(parts, p.parts...)
	return nil
}

type Value interface {
	MtEntry() (*big.Int, error)

	IsTime() bool
	AsTime() (time.Time, error)

	IsString() bool
	AsString() (string, error)

	IsInt64() bool
	AsInt64() (int64, error)

	IsBigInt() bool
	AsBigInt() (*big.Int, error)

	IsBool() bool
	AsBool() (bool, error)
}

var ErrIncorrectType = errors.New("incorrect type")

type value struct {
	// valid types are: int64, string, bool, time.Time, *big.Int
	value  any
	hasher Hasher
}

// NewValue creates new Value
func NewValue(hasher Hasher, val any) (Value, error) {
	switch val.(type) {
	case int64, string, bool, time.Time, *big.Int:
	default:
		return nil, ErrIncorrectType
	}
	return &value{value: val, hasher: hasher}, nil
}

// MtEntry returns Merkle Tree entry for the value
func (v *value) MtEntry() (*big.Int, error) {
	return mkValueMtEntry(v.hasher, v.value)
}

// IsTime returns true is value is of type time.Time
func (v *value) IsTime() bool {
	_, ok := v.value.(time.Time)
	return ok
}

// AsTime returns time.Time value or error if value is not Time.
func (v *value) AsTime() (time.Time, error) {
	tm, ok := v.value.(time.Time)
	if !ok {
		return time.Time{}, ErrIncorrectType
	}
	return tm, nil
}

// IsString returns true is value is of type string
func (v *value) IsString() bool {
	_, ok := v.value.(string)
	return ok
}

// AsString returns string value or error if value is not of type string
func (v *value) AsString() (string, error) {
	str, ok := v.value.(string)
	if !ok {
		return "", ErrIncorrectType
	}
	return str, nil
}

// IsInt64 returns true is value is of type int64
func (v *value) IsInt64() bool {
	_, ok := v.value.(int64)
	return ok
}

// AsInt64 returns int64 value or error if value is not of type int64
func (v *value) AsInt64() (int64, error) {
	i64, ok := v.value.(int64)
	if !ok {
		return 0, ErrIncorrectType
	}
	return i64, nil
}

// IsBool returns true is value is of type bool
func (v *value) IsBool() bool {
	_, ok := v.value.(bool)
	return ok
}

// AsBool returns bool value or error if value is not of type bool
func (v *value) AsBool() (bool, error) {
	b, ok := v.value.(bool)
	if !ok {
		return false, ErrIncorrectType
	}
	return b, nil
}

// IsBigInt returns true is value is of type *big.Int
func (v *value) IsBigInt() bool {
	_, ok := v.value.(*big.Int)
	return ok
}

// AsBigInt returns *big.Int value or error if value is not of type *big.Int
func (v *value) AsBigInt() (*big.Int, error) {
	i, ok := v.value.(*big.Int)
	if !ok {
		return nil, ErrIncorrectType
	}
	return i, nil
}

type nodeType uint8

const (
	nodeTypeUndefined nodeType = iota //nolint:deadcode,varcheck //for default value
	nodeTypeBlank
	nodeTypeIRI
	nodeTypeLiteral //nolint:deadcode,varcheck //may be used in future
)

// dataset index contains a name of the graph and quad index in quads array
type datasetIdx struct {
	graph string
	idx   int
}

type relationship struct {
	// mapping from child Subject to its parent
	parents map[datasetIdx]datasetIdx
	// mapping from subject for each child of parent node to this child's
	// index. If number of entries in map[refTp]int is 1, then
	// this parent node qArrKey has only one direct child, not array.
	children map[qArrKey]map[refTp]int
	hasher   Hasher
}

var errParentNotFound = errors.New("parent not found")
var errMultipleParentsFound = errors.New("multiple parents found")
var errInvalidReferenceType = errors.New("invalid reference type")
var errGraphNotFound = errors.New("graph not found")
var errQuadNotFound = errors.New("quad not found")

type refTp struct {
	tp  nodeType
	val string
}

func getRef(n ld.Node) (refTp, error) {
	switch nt := n.(type) {
	case *ld.IRI:
		return refTp{tp: nodeTypeIRI, val: nt.Value}, nil
	case *ld.BlankNode:
		return refTp{tp: nodeTypeBlank, val: nt.Attribute}, nil
	default:
		return refTp{}, errInvalidReferenceType
	}
}

func findParentInsideGraph(ds *ld.RDFDataset, q *ld.Quad) (datasetIdx, error) {
	graphName, err := getGraphName(q)
	if err != nil {
		return datasetIdx{}, err
	}

	quads, graphExists := ds.Graphs[graphName]
	if !graphExists {
		return datasetIdx{}, errGraphNotFound
	}

	qKey, err := getRef(q.Subject)
	if err != nil {
		return datasetIdx{}, err
	}
	found := false
	var result datasetIdx
	for idx, quad := range quads {
		if quad == q {
			continue
		}

		objKey, err := getRef(quad.Object)
		if err == errInvalidReferenceType {
			continue
		} else if err != nil {
			return datasetIdx{}, err
		}

		if qKey == objKey {
			if found {
				return datasetIdx{}, errMultipleParentsFound
			}
			found = true
			result = datasetIdx{graphName, idx}
		}
	}

	if found {
		return result, nil
	} else {
		return datasetIdx{}, errParentNotFound
	}
}

func findGraphParent(ds *ld.RDFDataset, q *ld.Quad) (datasetIdx, error) {
	if q.Graph == nil {
		return datasetIdx{}, errParentNotFound
	}

	qKey, err := getRef(q.Graph)
	if err != nil {
		return datasetIdx{}, err
	}
	if qKey.tp != nodeTypeBlank {
		return datasetIdx{}, errors.New("graph parent can only be a blank node")
	}

	found := false
	var result datasetIdx

	for graphName, quads := range ds.Graphs {
		for idx, quad := range quads {
			if quad == q {
				continue
			}

			objKey, err := getRef(quad.Object)
			if err == errInvalidReferenceType {
				continue
			} else if err != nil {
				return datasetIdx{}, err
			}

			if qKey == objKey {
				if found {
					return datasetIdx{}, errMultipleParentsFound
				}
				found = true
				result = datasetIdx{graphName, idx}
			}
		}
	}

	if found {
		return result, nil
	} else {
		return datasetIdx{}, errParentNotFound
	}
}

func findParent(ds *ld.RDFDataset, q *ld.Quad) (datasetIdx, error) {
	parent, err := findParentInsideGraph(ds, q)
	if err == nil {
		return parent, nil
	}

	if err != errParentNotFound {
		return datasetIdx{}, err
	}

	return findGraphParent(ds, q)
}

type qArrKey struct {
	subject   refTp
	predicate ld.IRI
	graph     string
}

func mkQArrKey(q *ld.Quad) (qArrKey, error) {
	var key qArrKey
	var err error
	key.graph, err = getGraphName(q)
	if err != nil {
		return key, err
	}

	switch s := q.Subject.(type) {
	case *ld.IRI:
		key.subject.tp = nodeTypeIRI
		key.subject.val = s.Value
	case *ld.BlankNode:
		key.subject.tp = nodeTypeBlank
		key.subject.val = s.Attribute
	default:
		return key, errors.New("invalid subject type")
	}

	switch p := q.Predicate.(type) {
	case *ld.IRI:
		key.predicate = *p
	default:
		return key, errors.New("invalid predicate type")
	}

	return key, nil
}

// iterate over graphs in consistent order
func iterGraphsOrdered(ds *ld.RDFDataset,
	fn func(graphName string, quads []*ld.Quad) error) error {

	var graphNames = make([]string, 0, len(ds.Graphs))
	for graphName := range ds.Graphs {
		graphNames = append(graphNames, graphName)
	}
	sort.Strings(graphNames)

	for _, graphName := range graphNames {
		quads := ds.Graphs[graphName]

		err := fn(graphName, quads)
		if err != nil {
			return err
		}
	}
	return nil
}

func newRelationship(ds *ld.RDFDataset, hasher Hasher) (*relationship,
	error) {
	r := relationship{
		parents:  make(map[datasetIdx]datasetIdx),
		children: make(map[qArrKey]map[refTp]int),
		hasher:   hasher,
	}
	if r.hasher == nil {
		r.hasher = defaultHasher
	}

	err := iterGraphsOrdered(ds,
		func(graphName string, quads []*ld.Quad) error {
			for idx, q := range quads {
				parentIdx, err := findParent(ds, q)
				if errors.Is(err, errParentNotFound) {
					continue
				} else if err != nil {
					return err
				}
				qIdx := datasetIdx{graphName, idx}
				r.parents[qIdx] = parentIdx

				parentQuad, err := getQuad(ds, parentIdx)
				if err != nil {
					return err
				}

				qKey, err := mkQArrKey(parentQuad)
				if err != nil {
					return err
				}

				childrenM, parentExists := r.children[qKey]
				if !parentExists {
					childrenM = make(map[refTp]int)
					r.children[qKey] = childrenM
				}

				childRef, err := getRef(q.Subject)
				if err != nil {
					return err
				}

				_, childExists := childrenM[childRef]
				if !childExists {
					nextIdx := len(childrenM)
					childrenM[childRef] = nextIdx
				}
			}
			return nil
		})
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func getQuad(ds *ld.RDFDataset, idx datasetIdx) (*ld.Quad, error) {
	quads, graphExists := ds.Graphs[idx.graph]
	if !graphExists {
		return nil, errGraphNotFound
	}

	if idx.idx >= len(quads) {
		return nil, errQuadNotFound
	}

	return quads[idx.idx], nil
}

func (r *relationship) path(dsIdx datasetIdx, ds *ld.RDFDataset,
	idx *int) (Path, error) {

	var k = Path{hasher: r.hasher}

	if idx != nil {
		err := k.Append(*idx)
		if err != nil {
			return k, err
		}
	}

	n, err := getQuad(ds, dsIdx)
	if err != nil {
		return k, err
	}

	var predicate *ld.IRI
	predicate, err = getIriValue(n.Predicate)
	if err != nil {
		return k, err
	}

	err = k.Append(predicate.Value)
	if err != nil {
		return k, err
	}

	nextKey := dsIdx
	for {
		parentIdx, ok := r.parents[nextKey]
		if !ok {
			break
		}

		var parent *ld.Quad
		parent, err = getQuad(ds, parentIdx)
		if err != nil {
			return k, err
		}

		parentKey, err := mkQArrKey(parent)
		if err != nil {
			return k, err
		}

		childrenMap, parentMappingExists := r.children[parentKey]
		if !parentMappingExists {
			return k, errors.New("parent mapping not found")
		}

		childQuad, err := getQuad(ds, nextKey)
		if err != nil {
			return k, err
		}
		childRef, err := getRef(childQuad.Subject)
		if err != nil {
			return k, err
		}
		childIdx, childFound := childrenMap[childRef]
		if !childFound {
			return k, errors.New("child not found in parents mapping")
		}

		var parentPredicate *ld.IRI
		parentPredicate, err = getIriValue(parent.Predicate)
		if err != nil {
			return k, err
		}

		if len(childrenMap) == 1 {
			err = k.Append(parentPredicate.Value)
		} else {
			err = k.Append(childIdx, parentPredicate.Value)
		}
		if err != nil {
			return k, err
		}

		nextKey = parentIdx
	}

	k.reverse()
	return k, nil
}

func getIriValue(n ld.Node) (*ld.IRI, error) {
	switch qp := n.(type) {
	case *ld.IRI:
		if qp == nil {
			return nil, errors.New("IRI is nil")
		}
		return qp, nil
	default:
		return nil, errors.New("type is not *ld.IRI")
	}

}

var dateRE = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

// EntriesFromRDF creates entries from RDF dataset suitable to add to
// merkle tree
func EntriesFromRDF(ds *ld.RDFDataset) ([]RDFEntry, error) {
	return EntriesFromRDFWithHasher(ds, defaultHasher)
}

// EntriesFromRDFWithHasher creates entries from RDF dataset suitable to add to with a provided Hasher
// merkle tree
func EntriesFromRDFWithHasher(ds *ld.RDFDataset,
	hasher Hasher) ([]RDFEntry, error) {

	// check graph naming assertions for dataset
	if err := assertDatasetConsistency(ds); err != nil {
		return nil, err
	}

	quads, ok := ds.Graphs[defaultGraphNodeName]
	if !ok {
		return nil, errors.New("@default graph not found in dataset")
	}

	if hasher == nil {
		hasher = defaultHasher
	}

	rs, err := newRelationship(ds, hasher)
	if err != nil {
		return nil, err
	}

	entries := make([]RDFEntry, 0, len(quads))
	graphProcessor := func(graphName string, quads []*ld.Quad) error {
		counts, err := countEntries(quads)
		if err != nil {
			return err
		}
		seenCount := make(map[qArrKey]int)

		for quadIdx, q := range quads {
			quadGraphIdx := datasetIdx{graphName, quadIdx}
			qKey, err := mkQArrKey(q)
			if err != nil {
				return err
			}
			var e RDFEntry
			switch qo := q.Object.(type) {
			case *ld.Literal:
				if qo == nil {
					return errors.New("object Literal is nil")
				}
				e.value, err = convertStringToXSDValue(qo.Datatype, qo.Value,
					hasher.Prime())
				if err != nil {
					return err
				}
				e.datatype = qo.Datatype
			case *ld.IRI:
				if qo == nil {
					return errors.New("object IRI is nil")
				}
				e.value = qo.GetValue()
			case *ld.BlankNode:
				if _, ok := rs.children[qKey]; ok {
					// this node is a reference to known parent,
					// skip it and do not put it into merkle tree because it
					// will be used as parent for other nodes, but has
					// no value to put itself.
					continue
				}
				return errors.New("BlankNode is not supported yet")
			default:
				return errors.New("unexpected Quad's Object type")
			}

			var idx *int
			switch counts[qKey] {
			case 0:
				return errors.New("[assertion] key not found in counts")
			case 1:
				// leave idx nil: only one element, do not consider it as an array
			default:
				idx = new(int)
				*idx = seenCount[qKey]
				seenCount[qKey]++
			}
			e.key, err = rs.path(quadGraphIdx, ds, idx)
			if err != nil {
				return err
			}

			entries = append(entries, e)
		}
		return nil
	}
	if err := iterGraphsOrdered(ds, graphProcessor); err != nil {
		return nil, err
	}
	return entries, nil
}

// HashValue hashes value according to datatype.
func HashValue(datatype string, value any) (*big.Int, error) {
	return valueToHash(defaultHasher, datatype, value)
}

// HashValueWithHasher hashes value according to datatype with a provided Hasher.
func HashValueWithHasher(h Hasher, datatype string, value any) (*big.Int, error) {
	return valueToHash(h, datatype, value)
}

func valueToHash(h Hasher, datatype string, value any) (*big.Int, error) {
	v, err := convertAnyToString(value, datatype)
	if err != nil {
		return nil, err
	}
	xsdValue, err := convertStringToXSDValue(datatype, v, h.Prime())
	if err != nil {
		return nil, err
	}
	return mkValueMtEntry(h, xsdValue)
}

// only supported xsd types.
func convertAnyToString(value any, datatype string) (str string, err error) {
	if datatype == ld.XSDDouble {
		switch v := value.(type) {
		case string:
			f, err := strconv.ParseFloat(v, 64)
			if err != nil {
				return "", err
			}
			return ld.GetCanonicalDouble(f), nil
		case int:
			return intToXSDDoubleStr(v)
		case int8:
			return intToXSDDoubleStr(v)
		case int16:
			return intToXSDDoubleStr(v)
		case int32:
			return intToXSDDoubleStr(v)
		case int64:
			return intToXSDDoubleStr(v)
		case uint:
			return uintToXSDDoubleStr(v)
		case uint8:
			return uintToXSDDoubleStr(v)
		case uint16:
			return uintToXSDDoubleStr(v)
		case uint32:
			return uintToXSDDoubleStr(v)
		case uint64:
			return uintToXSDDoubleStr(v)
		}
	}

	switch v := value.(type) {
	case float64:
		// https://www.w3.org/TR/2014/REC-json-ld-api-20140116/#data-round-tripping
		str = ld.GetCanonicalDouble(v)
	case float32:
		str = ld.GetCanonicalDouble(float64(v))
	case string:
		str = fmt.Sprintf("%v", v)
	case int64, int32, int16, int8, int, bool:
		str = fmt.Sprintf("%v", v)
	default:
		return str, ErrorUnsupportedType
	}
	return str, nil
}

type allInts interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64
}

type allUInts interface {
	~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64
}

// We can't just compare uint64(float64(v)) == uint64(v) because
// 1) maxUint64 = 18446744073709551615
// 2) float64(maxUint64) == 1.8446744073709552e+19
// 3) uint64(float64(maxUint64)) == 18446744073709551615
// 4) 1.8446744073709552 * 10**19 == 18446744073709552000
// 5) 18446744073709551615 != 18446744073709552000
// So hashes for 18446744073709551615 and 18446744073709551614 would be
// the same, which is not correct. That is why we use big.Rat here to check
// that float can represent integer value without loss of precision.
func intToXSDDoubleStr[T allInts](v T) (string, error) {
	out := ld.GetCanonicalDouble(float64(v))

	r := new(big.Rat)
	_, ok := r.SetString(out)
	if !ok {
		return "", errors.New(
			"[assertion] failed to parse canonical double as rational")
	}

	if r.Denom().Cmp(big.NewInt(1)) != 0 {
		return "", errors.New("value is too big to be converted to float64")
	}

	if r.Num().Cmp(big.NewInt(int64(v))) != 0 {
		return "", errors.New("value is too big to be converted to float64")
	}

	return out, nil
}

// see comment for intToXSDDoubleStr for explanations why this function
// uses big.Rat
func uintToXSDDoubleStr[T allUInts](v T) (string, error) {
	out := ld.GetCanonicalDouble(float64(v))

	r := new(big.Rat)
	_, ok := r.SetString(out)
	if !ok {
		return "", errors.New(
			"[assertion] failed to parse canonical double as rational")
	}

	if r.Denom().Cmp(big.NewInt(1)) != 0 {
		return "", errors.New("value is too big to be converted to float64")
	}

	if r.Num().Cmp(new(big.Int).SetUint64(uint64(v))) != 0 {
		return "", errors.New("value is too big to be converted to float64")
	}

	return out, nil
}

func intFromStr(s string) (*big.Int, error) {
	var r = new(big.Rat)
	_, ok := r.SetString(s)
	if !ok {
		return nil, fmt.Errorf("can't parse number: %v", s)
	}

	if !r.IsInt() {
		return nil, fmt.Errorf("integer has fractional part: %v", s)
	}

	return r.Num(), nil
}

// return included minimum and included maximum values for integers by XSD type
func minMaxByXSDType(xsdType string,
	prime *big.Int) (*big.Int, *big.Int, error) {
	switch xsdType {
	case ld.XSDNS + "positiveInteger":
		return big.NewInt(1), new(big.Int).Sub(prime, big.NewInt(1)), nil
	case ld.XSDNS + "nonNegativeInteger":
		return big.NewInt(0), new(big.Int).Sub(prime, big.NewInt(1)), nil
	case ld.XSDInteger:
		minVal, maxVal := minMaxFromPrime(prime)
		return minVal, maxVal, nil
	case ld.XSDNS + "negativeInteger":
		minVal, _ := minMaxFromPrime(prime)
		return minVal, big.NewInt(-1), nil
	case ld.XSDNS + "nonPositiveInteger":
		minVal, _ := minMaxFromPrime(prime)
		return minVal, big.NewInt(0), nil
	default:
		return nil, nil, fmt.Errorf("unsupported XSD type: %s", xsdType)
	}
}

func convertStringToXSDValue(datatype string, value string,
	maxFieldValue *big.Int) (resultValue interface{}, err error) {

	switch datatype {
	case ld.XSDBoolean:
		switch value {
		case "false", "0", "0.0E0":
			resultValue = false
		case "true", "1", "1.0E0":
			resultValue = true
		default:
			err = errors.New("incorrect boolean value")
		}

	case ld.XSDNS + "positiveInteger",
		ld.XSDNS + "nonNegativeInteger",
		ld.XSDInteger,
		ld.XSDNS + "negativeInteger",
		ld.XSDNS + "nonPositiveInteger":

		var i *big.Int
		i, err = intFromStr(value)
		if err != nil {
			break
		}

		var minVal, maxVal *big.Int
		minVal, maxVal, err = minMaxByXSDType(datatype, maxFieldValue)
		if err != nil {
			break
		}

		if i.Cmp(maxVal) > 0 {
			err = fmt.Errorf("integer exceeds maximum value: %v",
				i.String())
			break
		}

		if i.Cmp(minVal) < 0 {
			err = fmt.Errorf("integer is below minimum value: %v",
				i.String())
			break
		}

		resultValue = i

	case ld.XSDNS + "dateTime":
		if dateRE.MatchString(value) {
			resultValue, err = time.ParseInLocation("2006-01-02", value,
				time.UTC)
		} else {
			resultValue, err = time.Parse(time.RFC3339Nano, value)
		}

	case ld.XSDDouble:
		var f float64
		f, err = strconv.ParseFloat(value, 64)
		if err != nil {
			return "", err
		}
		resultValue = ld.GetCanonicalDouble(f)

	default:
		resultValue = value
	}

	return resultValue, err
}

// count number of entries with same key to distinguish between plain values
// and arrays (sets)
func countEntries(nodes []*ld.Quad) (map[qArrKey]int, error) {
	res := make(map[qArrKey]int, len(nodes))
	for _, q := range nodes {
		key, err := mkQArrKey(q)
		if err != nil {
			return nil, err
		}
		res[key]++
	}
	return res, nil
}

const defaultGraphNodeName = "@default"

func getGraphName(quad *ld.Quad) (string, error) {
	if quad.Graph == nil {
		return defaultGraphNodeName, nil
	}

	iri, ok := quad.Graph.(*ld.BlankNode)
	if !ok {
		return "", errors.New("graph node is not of *ld.BlankNode type")
	}

	return iri.Attribute, nil
}

type mtAppender interface {
	Add(context.Context, *big.Int, *big.Int) error
}

func AddEntriesToMerkleTree(ctx context.Context, mt mtAppender,
	entries []RDFEntry) error {

	for _, e := range entries {
		key, val, err := e.KeyValueMtEntries()
		if err != nil {
			return err
		}

		err = mt.Add(ctx, key, val)
		if err != nil {
			return err
		}
	}

	return nil
}

// Hasher is an interface to hash data
type Hasher interface {
	Hash(inpBI []*big.Int) (*big.Int, error)
	HashBytes(msg []byte) (*big.Int, error)
	Prime() *big.Int
}

// PoseidonHasher is an applier of poseidon hash algorithm
type PoseidonHasher struct{}

// Hash returns poseidon hash on big int params
func (p PoseidonHasher) Hash(inpBI []*big.Int) (*big.Int, error) {
	return poseidon.Hash(inpBI)
}

// HashBytes returns poseidon hash on bytes
func (p PoseidonHasher) HashBytes(msg []byte) (*big.Int, error) {
	return poseidon.HashBytes(msg)
}

// Prime returns Q constant
func (p PoseidonHasher) Prime() *big.Int {
	return new(big.Int).Set(constants.Q)
}

// MerkleTree is merkle tree structure
type MerkleTree interface {
	Add(context.Context, *big.Int, *big.Int) error
	GenerateProof(context.Context, *big.Int) (*merkletree.Proof, error)
	Root() *merkletree.Hash
}

type mtSQLAdapter merkletree.MerkleTree

// Add adds entry to tree
func (a *mtSQLAdapter) Add(ctx context.Context, key, value *big.Int) error {
	return (*merkletree.MerkleTree)(a).Add(ctx, key, value)
}

// GenerateProof generates proof
func (a *mtSQLAdapter) GenerateProof(ctx context.Context,
	key *big.Int) (*merkletree.Proof, error) {
	p, _, err := (*merkletree.MerkleTree)(a).GenerateProof(ctx, key, nil)
	return p, err
}

// Root return merkle tree root
func (a *mtSQLAdapter) Root() *merkletree.Hash {
	return (*merkletree.MerkleTree)(a).Root()
}

// MerkleTreeSQLAdapter is merkle tree sql adapter
func MerkleTreeSQLAdapter(mt *merkletree.MerkleTree) MerkleTree {
	return (*mtSQLAdapter)(mt)
}

// Merklizer is a struct to work with json-ld doc merklization
type Merklizer struct {
	srcDoc         []byte
	compacted      map[string]interface{}
	mt             MerkleTree
	entries        map[string]RDFEntry
	hasher         Hasher
	safeMode       bool
	ipfsCli        loaders.IPFSClient // @formatter:off : Goland bug
	ipfsGW         string
	documentLoader ld.DocumentLoader
}

// MerklizeOption is options for merklizer
type MerklizeOption func(m *Merklizer)

// WithHasher sets Hasher option
func WithHasher(h Hasher) MerklizeOption {
	return func(m *Merklizer) {
		m.hasher = h
	}
}

// WithMerkleTree sets MerkleTree option
func WithMerkleTree(mt MerkleTree) MerklizeOption {
	return func(m *Merklizer) {
		m.mt = mt
	}
}

// WithSafeMode enables the Safe mode when extending a JSON-LD document.
// The default setting for this mode is "true". If the function encounters
// an unknown field with an incorrect IRI predicate, it will return an error.
// However, if the Safe mode is set to "false", the function will simply skip
// the incorrect field and continue the merklization process without it.
func WithSafeMode(safeMode bool) MerklizeOption {
	return func(m *Merklizer) {
		m.safeMode = safeMode
	}
}

// WithIPFSClient sets IPFS client option required to resolve ipfs:// contexts.
// It works only if documentLoader is not set using WithDocumentLoader option.
// Otherwise, it will be ignored.
func WithIPFSClient(ipfsCli loaders.IPFSClient) MerklizeOption {
	return func(m *Merklizer) {
		m.ipfsCli = ipfsCli
	}
}

// WithIPFSGateway sets IPFS gateway URL option required to resolve
// ipfs:// contexts.
//
// If WithIPFSClient option is set, gateway would be ignored and ipfs requests
// would be sent directly to the client.
//
// If WithDocumentLoader option is set, gateway would be ignored and documents
// would be loaded using the document loader.
func WithIPFSGateway(ipfsGW string) MerklizeOption {
	return func(m *Merklizer) {
		m.ipfsGW = ipfsGW
	}
}

// WithDocumentLoader sets DocumentLoader
func WithDocumentLoader(documentLoader ld.DocumentLoader) MerklizeOption {
	return func(m *Merklizer) {
		m.documentLoader = documentLoader
	}
}

// MerklizeJSONLD takes a JSON-LD document, parses it and returns a
// Merklizer
func MerklizeJSONLD(ctx context.Context, in io.Reader,
	opts ...MerklizeOption) (*Merklizer, error) {

	mz := &Merklizer{safeMode: true}
	for _, o := range opts {
		o(mz)
	}

	// if merkletree is not set with options, initialize new in-memory MT.
	if mz.mt == nil {
		mt, err := merkletree.NewMerkleTree(ctx, memory.NewMemoryStorage(), 40)
		if err != nil {
			return nil, err
		}
		mz.mt = MerkleTreeSQLAdapter(mt)
	}

	// if hasher is not set with options, initialize it to default
	if mz.hasher == nil {
		mz.hasher = defaultHasher
	}

	var err error
	mz.srcDoc, err = io.ReadAll(in)
	if err != nil {
		return nil, err
	}

	var obj map[string]interface{}
	err = json.Unmarshal(mz.srcDoc, &obj)
	if err != nil {
		return nil, err
	}

	proc := ld.NewJsonLdProcessor()
	options := newJSONLDOptions(mz.safeMode, mz.getDocumentLoader())
	normDoc, err := proc.Normalize(obj, options)
	if err != nil {
		return nil, err
	}

	dataset, ok := normDoc.(*ld.RDFDataset)
	if !ok {
		return nil, errors.New("[assertion] expected *ld.RDFDataset type")
	}

	entries, err := EntriesFromRDFWithHasher(dataset, mz.hasher)
	if err != nil {
		return nil, err
	}

	mz.entries = make(map[string]RDFEntry, len(entries))
	for _, e := range entries {
		var key *big.Int
		key, err = e.KeyMtEntry()
		if err != nil {
			return nil, err
		}
		mz.entries[key.String()] = e
	}

	err = AddEntriesToMerkleTree(ctx, mz.mt, entries)
	if err != nil {
		return nil, err
	}

	mz.compacted, err = proc.Compact(obj, nil, options)
	return mz, err
}

func (mz *Merklizer) Entry(path Path) (RDFEntry, error) {
	key, err := path.MtEntry()
	if err != nil {
		return RDFEntry{}, err
	}
	e, ok := mz.entries[key.String()]
	if !ok {
		return RDFEntry{}, ErrorEntryNotFound
	}

	return e, nil
}

func (mz *Merklizer) getDocumentLoader() ld.DocumentLoader {
	if mz.documentLoader != nil {
		return mz.documentLoader
	}
	if mz.ipfsCli == nil && mz.ipfsGW == "" {
		return defaultDocumentLoader
	}
	return loaders.NewDocumentLoader(mz.ipfsCli, mz.ipfsGW)
}

func rvExtractObjField(obj any, field string) (any, error) {
	jsObj, isJSONObj := obj.(map[string]any)
	if !isJSONObj {
		return nil, errors.New("expected object")
	}

	graphObj, embeddedGraphExists := jsObj["@graph"]
	if len(jsObj) == 1 && embeddedGraphExists {
		var isGraphObjValid bool
		jsObj, isGraphObjValid = graphObj.(map[string]any)
		if !isGraphObjValid {
			return nil, errors.New("embedded graph of unexpected type")
		}
	}

	var fieldExists bool
	obj, fieldExists = jsObj[field]
	if !fieldExists {
		return nil, errors.New("value not found")
	}
	return obj, nil
}

func rvExtractArrayIdx(obj any, idx int) (any, error) {
	objArr, isArray := obj.([]any)
	if !isArray {
		return nil, errors.New("expected array")
	}
	if idx < 0 || idx >= len(objArr) {
		return nil, errors.New("index is out of range")
	}
	return objArr[idx], nil
}

func (mz *Merklizer) RawValue(path Path) (any, error) {
	parts := path.Parts()
	var obj any = mz.compacted
	var err error
	var traversedParts []string
	currentPath := func() string { return strings.Join(traversedParts, " / ") }

	for len(parts) > 0 {
		switch field := parts[0].(type) {
		case string:
			traversedParts = append(traversedParts, field)
			obj, err = rvExtractObjField(obj, field)
		case int:
			traversedParts = append(traversedParts, fmt.Sprintf("[%v]", field))
			obj, err = rvExtractArrayIdx(obj, field)
		default:
			err = errors.New("unexpected type of path")
		}
		if err != nil {
			return nil, fmt.Errorf("%v at '%v'", err, currentPath())
		}
		parts = parts[1:]
	}

	if jsObj, isJSONObj := obj.(map[string]any); isJSONObj {
		if val, hasValue := jsObj["@value"]; hasValue {
			return val, nil
		}
	}

	return obj, nil
}

// JSONLDType returns the JSON-LD type of the given path. If there is no literal
// by this path, it returns an error.
func (mz *Merklizer) JSONLDType(path Path) (string, error) {
	entry, err := mz.Entry(path)
	if err != nil {
		return "", err
	}
	return entry.datatype, nil
}

func (mz *Merklizer) ResolveDocPath(path string) (Path, error) {
	opts := Options{
		Hasher:         mz.hasher,
		DocumentLoader: mz.getDocumentLoader(),
	}
	if opts.Hasher == nil {
		opts.Hasher = defaultHasher
	}

	realPath, err := opts.NewPathFromDocument(mz.srcDoc, path)
	if err != nil {
		return Path{}, err
	}
	return realPath, nil
}

func (mz *Merklizer) Options() Options {
	return Options{
		Hasher:         mz.hasher,
		DocumentLoader: mz.getDocumentLoader(),
	}
}

// Proof generate and return Proof and Value by the given Path.
// If the path is not found, it returns nil as value interface.
func (mz *Merklizer) Proof(ctx context.Context,
	path Path) (*merkletree.Proof, Value, error) {

	keyHash, err := path.MtEntry()
	if err != nil {
		return nil, nil, err
	}

	proof, err := mz.mt.GenerateProof(ctx, keyHash)
	if err != nil {
		return nil, nil, err
	}

	var value Value
	if proof.Existence {
		entry, ok := mz.entries[keyHash.String()]
		if !ok {
			return nil, nil, errors.New(
				"[assertion] no Entry found while existence is true")
		}
		value, err = NewValue(mz.hasher, entry.value)
		if err != nil {
			return nil, nil, err
		}
	}

	return proof, value, err
}

func (mz *Merklizer) MkValue(val any) (Value, error) {
	return NewValue(mz.hasher, val)
}

func (mz *Merklizer) Root() *merkletree.Hash {
	return mz.mt.Root()
}

func (mz *Merklizer) Hasher() Hasher {
	return mz.hasher
}

func mkValueMtEntry(h Hasher, v interface{}) (*big.Int, error) {
	switch et := v.(type) {
	case int64:
		return mkValueInt(h, et)
	case int32:
		return mkValueInt(h, et)
	case int:
		return mkValueInt(h, et)
	case uint64:
		return mkValueUInt(et)
	case uint32:
		return mkValueUInt(et)
	case uint:
		return mkValueUInt(et)
	case bool:
		return mkValueBool(h, et)
	case string:
		return mkValueString(h, et)
	case time.Time:
		return mkValueTime(h, et)
	case *big.Int:
		return mkValueBigInt(h, et)
	default:
		return nil, fmt.Errorf("unexpected value type: %T", v)
	}
}

func mkValueInt[I int64 | int32 | int](h Hasher, val I) (*big.Int, error) {
	if val >= 0 {
		return big.NewInt(int64(val)), nil
	} else {
		return new(big.Int).Add(h.Prime(), big.NewInt(int64(val))), nil
	}
}

func mkValueUInt[I uint64 | uint32 | uint](val I) (*big.Int, error) {
	return new(big.Int).SetUint64(uint64(val)), nil
}

func mkValueBool(h Hasher, val bool) (*big.Int, error) {
	if val {
		return h.Hash([]*big.Int{big.NewInt(1)})
	} else {
		return h.Hash([]*big.Int{big.NewInt(0)})
	}
}

func mkValueString(h Hasher, val string) (*big.Int, error) {
	return h.HashBytes([]byte(val))
}

func mkValueTime(h Hasher, val time.Time) (*big.Int, error) {
	var x = new(big.Int).Mul(
		big.NewInt(val.Unix()),
		big.NewInt(1_000_000_000))
	x.Add(x, big.NewInt(int64(val.Nanosecond())))
	x.Mod(x, h.Prime())
	return x, nil
}

func mkValueBigInt(h Hasher, val *big.Int) (*big.Int, error) {
	if val.Cmp(h.Prime()) >= 0 {
		return nil, fmt.Errorf("value is too big: %v", val.String())
	}
	if val.Cmp(big.NewInt(0)) < 0 {
		minValue, _ := minMaxFromPrime(h.Prime())

		if val.Cmp(minValue) < 0 {
			return nil, fmt.Errorf("value is too small: %v",
				val.String())
		}

		return new(big.Int).Add(val, h.Prime()), nil
	}

	return val, nil
}

// assert consistency of dataset and validate that only
// quads we support contains in dataset.
func assertDatasetConsistency(ds *ld.RDFDataset) error {
	for graph, quads := range ds.Graphs {
		for _, q := range quads {
			if graph == "" {
				return errors.New("empty graph name")
			}

			if graph == defaultGraphNodeName && q.Graph != nil {
				return errors.New("graph should be nil for @default graph")
			}

			if q.Graph == nil && graph != defaultGraphNodeName {
				return errors.New(
					"graph should not be nil for non-@default graph")
			}

			if q.Graph != nil {
				n, ok := q.Graph.(*ld.BlankNode)
				if !ok {
					return errors.New("graph should be of type *ld.BlankNode")
				}

				if n.Attribute != graph {
					return errors.New(
						"graph name should be equal to graph attribute")
				}
			}

			// predicate should always be *ld.IRI
			_, ok := q.Predicate.(*ld.IRI)
			if !ok {
				return errors.New("predicate should be of type *ld.IRI")
			}
		}
	}
	return nil
}

func newJSONLDOptions(safeMode bool, docLoader ld.DocumentLoader) *ld.JsonLdOptions {
	options := ld.NewJsonLdOptions("")
	options.Algorithm = ld.AlgorithmURDNA2015
	options.SafeMode = safeMode
	options.DocumentLoader = docLoader
	return options
}

func minMaxFromPrime(primeVal *big.Int) (*big.Int, *big.Int) {
	maxValue := new(big.Int).Div(primeVal, big.NewInt(2))
	minValue := new(big.Int).Add(
		new(big.Int).Sub(maxValue, primeVal),
		big.NewInt(1))
	return minValue, maxValue
}
