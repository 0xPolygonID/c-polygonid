package protocol

import (
	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2"
)

const (
	// RevocationStatusRequestMessageType is type for request of revocation status
	RevocationStatusRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "revocation/1.0/request-status"
	// RevocationStatusResponseMessageType is type for response with a revocation status
	RevocationStatusResponseMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "revocation/1.0/status"
)

// RevocationStatusRequestMessage is struct the represents body for proof generation request
type RevocationStatusRequestMessage struct {
	ID       string                             `json:"id"`
	Typ      iden3comm.MediaType                `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage          `json:"type"`
	ThreadID string                             `json:"thid,omitempty"`
	Body     RevocationStatusRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// RevocationStatusRequestMessageBody is struct the represents request for revocation status
type RevocationStatusRequestMessageBody struct {
	RevocationNonce uint64 `json:"revocation_nonce"`
}

// RevocationStatusResponseMessage is struct the represents body for proof generation request
type RevocationStatusResponseMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body RevocationStatusResponseMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// RevocationStatusResponseMessageBody is struct the represents request for revocation status
type RevocationStatusResponseMessageBody struct {
	verifiable.RevocationStatus
}
