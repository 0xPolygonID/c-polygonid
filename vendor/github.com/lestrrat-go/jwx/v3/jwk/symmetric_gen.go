// Code generated by tools/cmd/genjwk/main.go. DO NOT EDIT.

package jwk

import (
	"bytes"
	"fmt"
	"sort"
	"sync"

	"github.com/lestrrat-go/blackmagic"
	"github.com/lestrrat-go/jwx/v3/cert"
	"github.com/lestrrat-go/jwx/v3/internal/base64"
	"github.com/lestrrat-go/jwx/v3/internal/json"
	"github.com/lestrrat-go/jwx/v3/internal/pool"
	"github.com/lestrrat-go/jwx/v3/jwa"
)

const (
	SymmetricOctetsKey = "k"
)

type SymmetricKey interface {
	Key
	Octets() ([]byte, bool)
}

type symmetricKey struct {
	algorithm              *jwa.KeyAlgorithm // https://tools.ietf.org/html/rfc7517#section-4.4
	keyID                  *string           // https://tools.ietf.org/html/rfc7515#section-4.1.4
	keyOps                 *KeyOperationList // https://tools.ietf.org/html/rfc7517#section-4.3
	keyUsage               *string           // https://tools.ietf.org/html/rfc7517#section-4.2
	octets                 []byte
	x509CertChain          *cert.Chain // https://tools.ietf.org/html/rfc7515#section-4.1.6
	x509CertThumbprint     *string     // https://tools.ietf.org/html/rfc7515#section-4.1.7
	x509CertThumbprintS256 *string     // https://tools.ietf.org/html/rfc7515#section-4.1.8
	x509URL                *string     // https://tools.ietf.org/html/rfc7515#section-4.1.5
	privateParams          map[string]interface{}
	mu                     *sync.RWMutex
	dc                     json.DecodeCtx
}

var _ SymmetricKey = &symmetricKey{}
var _ Key = &symmetricKey{}

func newSymmetricKey() *symmetricKey {
	return &symmetricKey{
		mu:            &sync.RWMutex{},
		privateParams: make(map[string]interface{}),
	}
}

func (h symmetricKey) KeyType() jwa.KeyType {
	return jwa.OctetSeq()
}

func (h *symmetricKey) Algorithm() (jwa.KeyAlgorithm, bool) {
	if h.algorithm != nil {
		return *(h.algorithm), true
	}
	return nil, false
}

func (h *symmetricKey) KeyID() (string, bool) {
	if h.keyID != nil {
		return *(h.keyID), true
	}
	return "", false
}

func (h *symmetricKey) KeyOps() (KeyOperationList, bool) {
	if h.keyOps != nil {
		return *(h.keyOps), true
	}
	return nil, false
}

func (h *symmetricKey) KeyUsage() (string, bool) {
	if h.keyUsage != nil {
		return *(h.keyUsage), true
	}
	return "", false
}

func (h *symmetricKey) Octets() ([]byte, bool) {
	if h.octets != nil {
		return h.octets, true
	}
	return nil, false
}

func (h *symmetricKey) X509CertChain() (*cert.Chain, bool) {
	return h.x509CertChain, true
}

func (h *symmetricKey) X509CertThumbprint() (string, bool) {
	if h.x509CertThumbprint != nil {
		return *(h.x509CertThumbprint), true
	}
	return "", false
}

func (h *symmetricKey) X509CertThumbprintS256() (string, bool) {
	if h.x509CertThumbprintS256 != nil {
		return *(h.x509CertThumbprintS256), true
	}
	return "", false
}

func (h *symmetricKey) X509URL() (string, bool) {
	if h.x509URL != nil {
		return *(h.x509URL), true
	}
	return "", false
}

func (h *symmetricKey) Has(name string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case AlgorithmKey:
		return h.algorithm != nil
	case KeyIDKey:
		return h.keyID != nil
	case KeyOpsKey:
		return h.keyOps != nil
	case KeyUsageKey:
		return h.keyUsage != nil
	case SymmetricOctetsKey:
		return h.octets != nil
	case X509CertChainKey:
		return h.x509CertChain != nil
	case X509CertThumbprintKey:
		return h.x509CertThumbprint != nil
	case X509CertThumbprintS256Key:
		return h.x509CertThumbprintS256 != nil
	case X509URLKey:
		return h.x509URL != nil
	default:
		_, ok := h.privateParams[name]
		return ok
	}
}

func (h *symmetricKey) Get(name string, dst interface{}) error {
	h.mu.RLock()
	defer h.mu.RUnlock()
	switch name {
	case KeyTypeKey:
		if err := blackmagic.AssignIfCompatible(dst, h.KeyType()); err != nil {
			return fmt.Errorf(`symmetricKey.Get: failed to assign value for field %q to destination object: %w`, name, err)
		}
	case AlgorithmKey:
		if h.algorithm == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.algorithm)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case KeyIDKey:
		if h.keyID == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.keyID)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case KeyOpsKey:
		if h.keyOps == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.keyOps)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case KeyUsageKey:
		if h.keyUsage == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.keyUsage)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case SymmetricOctetsKey:
		if h.octets == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.octets); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509CertChainKey:
		if h.x509CertChain == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, h.x509CertChain); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509CertThumbprintKey:
		if h.x509CertThumbprint == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.x509CertThumbprint)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509CertThumbprintS256Key:
		if h.x509CertThumbprintS256 == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.x509CertThumbprintS256)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	case X509URLKey:
		if h.x509URL == nil {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, *(h.x509URL)); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
		return nil
	default:
		v, ok := h.privateParams[name]
		if !ok {
			return fmt.Errorf(`field %q not found`, name)
		}
		if err := blackmagic.AssignIfCompatible(dst, v); err != nil {
			return fmt.Errorf(`failed to assign value for field %q: %w`, name, err)
		}
	}
	return nil
}

func (h *symmetricKey) Set(name string, value interface{}) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.setNoLock(name, value)
}

func (h *symmetricKey) setNoLock(name string, value interface{}) error {
	switch name {
	case "kty":
		return nil
	case AlgorithmKey:
		switch v := value.(type) {
		case string, jwa.SignatureAlgorithm, jwa.KeyEncryptionAlgorithm, jwa.ContentEncryptionAlgorithm:
			tmp, err := jwa.KeyAlgorithmFrom(v)
			if err != nil {
				return fmt.Errorf(`invalid algorithm for %q key: %w`, AlgorithmKey, err)
			}
			h.algorithm = &tmp
		default:
			return fmt.Errorf(`invalid type for %q key: %T`, AlgorithmKey, value)
		}
		return nil
	case KeyIDKey:
		if v, ok := value.(string); ok {
			h.keyID = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, KeyIDKey, value)
	case KeyOpsKey:
		var acceptor KeyOperationList
		if err := acceptor.Accept(value); err != nil {
			return fmt.Errorf(`invalid value for %s key: %w`, KeyOpsKey, err)
		}
		h.keyOps = &acceptor
		return nil
	case KeyUsageKey:
		switch v := value.(type) {
		case KeyUsageType:
			switch v {
			case ForSignature, ForEncryption:
				tmp := v.String()
				h.keyUsage = &tmp
			default:
				return fmt.Errorf(`invalid key usage type %s`, v)
			}
		case string:
			h.keyUsage = &v
		default:
			return fmt.Errorf(`invalid key usage type %s`, v)
		}
	case SymmetricOctetsKey:
		if v, ok := value.([]byte); ok {
			h.octets = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, SymmetricOctetsKey, value)
	case X509CertChainKey:
		if v, ok := value.(*cert.Chain); ok {
			h.x509CertChain = v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509CertChainKey, value)
	case X509CertThumbprintKey:
		if v, ok := value.(string); ok {
			h.x509CertThumbprint = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509CertThumbprintKey, value)
	case X509CertThumbprintS256Key:
		if v, ok := value.(string); ok {
			h.x509CertThumbprintS256 = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509CertThumbprintS256Key, value)
	case X509URLKey:
		if v, ok := value.(string); ok {
			h.x509URL = &v
			return nil
		}
		return fmt.Errorf(`invalid value for %s key: %T`, X509URLKey, value)
	default:
		if h.privateParams == nil {
			h.privateParams = map[string]interface{}{}
		}
		h.privateParams[name] = value
	}
	return nil
}

func (k *symmetricKey) Remove(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	switch key {
	case AlgorithmKey:
		k.algorithm = nil
	case KeyIDKey:
		k.keyID = nil
	case KeyOpsKey:
		k.keyOps = nil
	case KeyUsageKey:
		k.keyUsage = nil
	case SymmetricOctetsKey:
		k.octets = nil
	case X509CertChainKey:
		k.x509CertChain = nil
	case X509CertThumbprintKey:
		k.x509CertThumbprint = nil
	case X509CertThumbprintS256Key:
		k.x509CertThumbprintS256 = nil
	case X509URLKey:
		k.x509URL = nil
	default:
		delete(k.privateParams, key)
	}
	return nil
}

func (k *symmetricKey) Clone() (Key, error) {
	key, err := cloneKey(k)
	if err != nil {
		return nil, fmt.Errorf(`symmetricKey.Clone: %w`, err)
	}
	return key, nil
}

func (k *symmetricKey) DecodeCtx() json.DecodeCtx {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.dc
}

func (k *symmetricKey) SetDecodeCtx(dc json.DecodeCtx) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.dc = dc
}

func (h *symmetricKey) UnmarshalJSON(buf []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.algorithm = nil
	h.keyID = nil
	h.keyOps = nil
	h.keyUsage = nil
	h.octets = nil
	h.x509CertChain = nil
	h.x509CertThumbprint = nil
	h.x509CertThumbprintS256 = nil
	h.x509URL = nil
	dec := json.NewDecoder(bytes.NewReader(buf))
LOOP:
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf(`error reading token: %w`, err)
		}
		switch tok := tok.(type) {
		case json.Delim:
			// Assuming we're doing everything correctly, we should ONLY
			// get either '{' or '}' here.
			if tok == '}' { // End of object
				break LOOP
			} else if tok != '{' {
				return fmt.Errorf(`expected '{', but got '%c'`, tok)
			}
		case string: // Objects can only have string keys
			switch tok {
			case KeyTypeKey:
				val, err := json.ReadNextStringToken(dec)
				if err != nil {
					return fmt.Errorf(`error reading token: %w`, err)
				}
				if val != jwa.OctetSeq().String() {
					return fmt.Errorf(`invalid kty value for RSAPublicKey (%s)`, val)
				}
			case AlgorithmKey:
				var s string
				if err := dec.Decode(&s); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, AlgorithmKey, err)
				}
				alg, err := jwa.KeyAlgorithmFrom(s)
				if err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, AlgorithmKey, err)
				}
				h.algorithm = &alg
			case KeyIDKey:
				if err := json.AssignNextStringToken(&h.keyID, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, KeyIDKey, err)
				}
			case KeyOpsKey:
				var decoded KeyOperationList
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, KeyOpsKey, err)
				}
				h.keyOps = &decoded
			case KeyUsageKey:
				if err := json.AssignNextStringToken(&h.keyUsage, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, KeyUsageKey, err)
				}
			case SymmetricOctetsKey:
				if err := json.AssignNextBytesToken(&h.octets, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, SymmetricOctetsKey, err)
				}
			case X509CertChainKey:
				var decoded cert.Chain
				if err := dec.Decode(&decoded); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509CertChainKey, err)
				}
				h.x509CertChain = &decoded
			case X509CertThumbprintKey:
				if err := json.AssignNextStringToken(&h.x509CertThumbprint, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509CertThumbprintKey, err)
				}
			case X509CertThumbprintS256Key:
				if err := json.AssignNextStringToken(&h.x509CertThumbprintS256, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509CertThumbprintS256Key, err)
				}
			case X509URLKey:
				if err := json.AssignNextStringToken(&h.x509URL, dec); err != nil {
					return fmt.Errorf(`failed to decode value for key %s: %w`, X509URLKey, err)
				}
			default:
				if dc := h.dc; dc != nil {
					if localReg := dc.Registry(); localReg != nil {
						decoded, err := localReg.Decode(dec, tok)
						if err == nil {
							h.setNoLock(tok, decoded)
							continue
						}
					}
				}
				decoded, err := registry.Decode(dec, tok)
				if err == nil {
					h.setNoLock(tok, decoded)
					continue
				}
				return fmt.Errorf(`could not decode field %s: %w`, tok, err)
			}
		default:
			return fmt.Errorf(`invalid token %T`, tok)
		}
	}
	if h.octets == nil {
		return fmt.Errorf(`required field k is missing`)
	}
	return nil
}

func (h symmetricKey) MarshalJSON() ([]byte, error) {
	data := make(map[string]interface{})
	fields := make([]string, 0, 9)
	data[KeyTypeKey] = jwa.OctetSeq()
	fields = append(fields, KeyTypeKey)
	if h.algorithm != nil {
		data[AlgorithmKey] = *(h.algorithm)
		fields = append(fields, AlgorithmKey)
	}
	if h.keyID != nil {
		data[KeyIDKey] = *(h.keyID)
		fields = append(fields, KeyIDKey)
	}
	if h.keyOps != nil {
		data[KeyOpsKey] = *(h.keyOps)
		fields = append(fields, KeyOpsKey)
	}
	if h.keyUsage != nil {
		data[KeyUsageKey] = *(h.keyUsage)
		fields = append(fields, KeyUsageKey)
	}
	if h.octets != nil {
		data[SymmetricOctetsKey] = h.octets
		fields = append(fields, SymmetricOctetsKey)
	}
	if h.x509CertChain != nil {
		data[X509CertChainKey] = h.x509CertChain
		fields = append(fields, X509CertChainKey)
	}
	if h.x509CertThumbprint != nil {
		data[X509CertThumbprintKey] = *(h.x509CertThumbprint)
		fields = append(fields, X509CertThumbprintKey)
	}
	if h.x509CertThumbprintS256 != nil {
		data[X509CertThumbprintS256Key] = *(h.x509CertThumbprintS256)
		fields = append(fields, X509CertThumbprintS256Key)
	}
	if h.x509URL != nil {
		data[X509URLKey] = *(h.x509URL)
		fields = append(fields, X509URLKey)
	}
	for k, v := range h.privateParams {
		data[k] = v
		fields = append(fields, k)
	}

	sort.Strings(fields)
	buf := pool.GetBytesBuffer()
	defer pool.ReleaseBytesBuffer(buf)
	buf.WriteByte('{')
	enc := json.NewEncoder(buf)
	for i, f := range fields {
		if i > 0 {
			buf.WriteRune(',')
		}
		buf.WriteRune('"')
		buf.WriteString(f)
		buf.WriteString(`":`)
		v := data[f]
		switch v := v.(type) {
		case []byte:
			buf.WriteRune('"')
			buf.WriteString(base64.EncodeToString(v))
			buf.WriteRune('"')
		default:
			if err := enc.Encode(v); err != nil {
				return nil, fmt.Errorf(`failed to encode value for field %s: %w`, f, err)
			}
			buf.Truncate(buf.Len() - 1)
		}
	}
	buf.WriteByte('}')
	ret := make([]byte, buf.Len())
	copy(ret, buf.Bytes())
	return ret, nil
}

func (h *symmetricKey) Keys() []string {
	h.mu.RLock()
	defer h.mu.RUnlock()
	keys := make([]string, 0, 9+len(h.privateParams))
	keys = append(keys, KeyTypeKey)
	if h.algorithm != nil {
		keys = append(keys, AlgorithmKey)
	}
	if h.keyID != nil {
		keys = append(keys, KeyIDKey)
	}
	if h.keyOps != nil {
		keys = append(keys, KeyOpsKey)
	}
	if h.keyUsage != nil {
		keys = append(keys, KeyUsageKey)
	}
	if h.octets != nil {
		keys = append(keys, SymmetricOctetsKey)
	}
	if h.x509CertChain != nil {
		keys = append(keys, X509CertChainKey)
	}
	if h.x509CertThumbprint != nil {
		keys = append(keys, X509CertThumbprintKey)
	}
	if h.x509CertThumbprintS256 != nil {
		keys = append(keys, X509CertThumbprintS256Key)
	}
	if h.x509URL != nil {
		keys = append(keys, X509URLKey)
	}
	for k := range h.privateParams {
		keys = append(keys, k)
	}
	return keys
}
