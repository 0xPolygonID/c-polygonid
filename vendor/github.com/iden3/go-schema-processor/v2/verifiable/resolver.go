package verifiable

import (
	"context"
	"fmt"

	"github.com/iden3/go-iden3-core/v2/w3c"
)

type ctxKeyIssuerDID struct{}

// WithIssuerDID puts the issuer DID in the context
func WithIssuerDID(ctx context.Context, issuerDID *w3c.DID) context.Context {
	return context.WithValue(ctx, ctxKeyIssuerDID{}, issuerDID)
}

// GetIssuerDID extract the issuer DID from the context.
// Or nil if nothing is found.
func GetIssuerDID(ctx context.Context) *w3c.DID {
	v := ctx.Value(ctxKeyIssuerDID{})
	if v == nil {
		return nil
	}
	return v.(*w3c.DID)
}

// CredentialStatusResolver is an interface that allows to interact with deifferent types of credential status to resolve revocation status
type CredentialStatusResolver interface {
	Resolve(ctx context.Context,
		credentialStatus CredentialStatus) (RevocationStatus, error)
}

// CredentialStatusResolverRegistry is a registry of CredentialStatusResolver
type CredentialStatusResolverRegistry struct {
	resolvers map[CredentialStatusType]CredentialStatusResolver
}

func (r *CredentialStatusResolverRegistry) Register(resolverType CredentialStatusType, resolver CredentialStatusResolver) {
	if r.resolvers == nil {
		r.resolvers = make(map[CredentialStatusType]CredentialStatusResolver)
	}
	r.resolvers[resolverType] = resolver
}

func (r *CredentialStatusResolverRegistry) Get(resolverType CredentialStatusType) (CredentialStatusResolver, error) {
	resolver, ok := r.resolvers[resolverType]
	if !ok {
		return nil, fmt.Errorf("credential status type %s id not registered", resolverType)
	}
	return resolver, nil
}

func (r *CredentialStatusResolverRegistry) Delete(resolverType CredentialStatusType) {
	if r.resolvers == nil {
		return
	}
	delete(r.resolvers, resolverType)
}

var DefaultCredentialStatusResolverRegistry = &CredentialStatusResolverRegistry{}

func RegisterStatusResolver(resolverType CredentialStatusType,
	resolver CredentialStatusResolver) {

	DefaultCredentialStatusResolverRegistry.Register(resolverType, resolver)
}

func GetStatusResolver(
	resolverType CredentialStatusType) (CredentialStatusResolver, error) {

	return DefaultCredentialStatusResolverRegistry.Get(resolverType)
}

func DeleteStatusResolver(resolverType CredentialStatusType) {
	DefaultCredentialStatusResolverRegistry.Delete(resolverType)
}
