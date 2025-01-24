package resolvers

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/iden3/go-iden3-core/v2/w3c"
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
	"github.com/iden3/iden3comm/v2/packers"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/pkg/errors"
)

type ctxKeySenderDID struct{}

// WithSenderDID puts the user DID in the context
func WithSenderDID(ctx context.Context, userDID *w3c.DID) context.Context {
	return context.WithValue(ctx, ctxKeySenderDID{}, userDID)
}

// GetSenderDID extract the sender's DID from the context.
// Returns nil if nothing is found.
func GetSenderDID(ctx context.Context) *w3c.DID {
	v := ctx.Value(ctxKeySenderDID{})
	if v == nil {
		return nil
	}
	return v.(*w3c.DID)
}

// AgentResolverConfig options for credential status verification
type AgentResolverConfig struct {
	PackageManager   *iden3comm.PackageManager
	CustomHTTPClient *http.Client
}

// AgentResolver is a struct that allows to interact with the issuer's agent to get revocation status.
type AgentResolver struct {
	config AgentResolverConfig
}

// NewAgentResolver returns new agent resolver
func NewAgentResolver(config AgentResolverConfig) *AgentResolver {
	return &AgentResolver{config}
}

// Resolve is a method to resolve a credential status from an agent.
func (r AgentResolver) Resolve(ctx context.Context,
	status verifiable.CredentialStatus) (out verifiable.RevocationStatus, err error) {

	if status.Type != verifiable.Iden3commRevocationStatusV1 {
		return out, errors.New("invalid status type")
	}
	revocationBody := protocol.RevocationStatusRequestMessageBody{
		RevocationNonce: status.RevocationNonce,
	}
	rawBody, err := json.Marshal(revocationBody)
	if err != nil {
		return out, errors.WithStack(err)
	}

	idUUID, err := uuid.NewV7()
	if err != nil {
		return out, errors.WithStack(err)
	}
	threadUUID, err := uuid.NewV7()
	if err != nil {
		return out, errors.WithStack(err)
	}

	senderDID := GetSenderDID(ctx)
	if senderDID == nil {
		return out, errors.New("sender DID not found in the context")
	}
	issuerDID := verifiable.GetIssuerDID(ctx)
	if issuerDID == nil {
		return out, errors.New("issuer DID not found in the context")
	}
	msg := iden3comm.BasicMessage{
		ID:       idUUID.String(),
		ThreadID: threadUUID.String(),
		From:     senderDID.String(),
		To:       issuerDID.String(),
		Type:     protocol.RevocationStatusRequestMessageType,
		Body:     rawBody,
	}
	bytesMsg, err := json.Marshal(msg)
	if err != nil {
		return out, errors.WithStack(err)
	}

	iden3commMsg, err := r.config.PackageManager.Pack(packers.MediaTypePlainMessage, bytesMsg, nil)
	if err != nil {
		return out, errors.WithStack(err)
	}

	httpClient := http.DefaultClient
	if r.config.CustomHTTPClient != nil {
		httpClient = r.config.CustomHTTPClient
	}

	resp, err := httpClient.Post(status.ID, "application/json", bytes.NewBuffer(iden3commMsg))
	if err != nil {
		return out, errors.WithStack(err)
	}
	defer func() {
		err2 := resp.Body.Close()
		if err == nil {
			err = errors.WithStack(err2)
		}
	}()

	statusOK := resp.StatusCode >= 200 && resp.StatusCode < 300
	if !statusOK {
		return out, errors.Errorf("bad status code: %d", resp.StatusCode)
	}

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return out, errors.WithStack(err)
	}

	basicMessage, _, err := r.config.PackageManager.Unpack(b)
	if err != nil {
		return out, errors.WithStack(err)
	}

	if basicMessage.Type != protocol.RevocationStatusResponseMessageType {
		return out, errors.Errorf("unexpected message type: %s", basicMessage.Type)
	}

	var revocationStatus protocol.RevocationStatusResponseMessageBody
	if err = json.Unmarshal(basicMessage.Body, &revocationStatus); err != nil {
		return out, errors.WithStack(err)
	}

	return revocationStatus.RevocationStatus, err
}
