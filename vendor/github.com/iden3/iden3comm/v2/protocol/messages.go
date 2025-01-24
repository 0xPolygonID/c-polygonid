package protocol

import "github.com/iden3/iden3comm/v2"

const (
	// MessageFetchRequestMessageType defines message fetch request type of the communication protocol.
	MessageFetchRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "messages/1.0/fetch"
)

// MessageFetchRequestMessage represent Iden3message for message fetch request.
type MessageFetchRequestMessage struct {
	ID       string                    `json:"id"`
	Typ      iden3comm.MediaType       `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage `json:"type"`
	ThreadID string                    `json:"thid,omitempty"`

	Body MessageFetchRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// MessageFetchRequestMessageBody is struct the represents body for message fetch request.
type MessageFetchRequestMessageBody struct {
	ID string `json:"id"`
}
