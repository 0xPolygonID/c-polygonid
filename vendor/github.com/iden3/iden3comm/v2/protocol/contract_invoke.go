package protocol

import (
	"encoding/json"

	"github.com/iden3/iden3comm/v2"
)

const (
	// ContractInvokeRequestMessageType defines contract invoke request type of the communication protocol
	ContractInvokeRequestMessageType iden3comm.ProtocolMessage = iden3comm.Iden3Protocol + "proofs/1.0/contract-invoke-request"
)

// ContractInvokeRequestMessage is struct the represents iden3message contract invoke request
type ContractInvokeRequestMessage struct {
	ID       string                           `json:"id"`
	Typ      iden3comm.MediaType              `json:"typ,omitempty"`
	Type     iden3comm.ProtocolMessage        `json:"type"`
	ThreadID string                           `json:"thid,omitempty"`
	Body     ContractInvokeRequestMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// ContractInvokeRequestMessageBody is body for contract invoke request
type ContractInvokeRequestMessageBody struct {
	Reason          string                      `json:"reason,omitempty"`
	TransactionData TransactionData             `json:"transaction_data"`
	DIDDoc          json.RawMessage             `json:"did_doc,omitempty"`
	Scope           []ZeroKnowledgeProofRequest `json:"scope"`
}

// TransactionData represents structure for on chain verification
type TransactionData struct {
	ContractAddress string `json:"contract_address"`
	MethodID        string `json:"method_id"`
	ChainID         int    `json:"chain_id"`
	Network         string `json:"network"`
}
