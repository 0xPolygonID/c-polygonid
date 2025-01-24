package protocol

import (
	"strings"

	"github.com/iden3/iden3comm/v2"
	"github.com/pkg/errors"
)

const (
	// ProblemReportMessageType is type for problem report
	ProblemReportMessageType iden3comm.ProtocolMessage = iden3comm.DidCommProtocol + "report-problem/2.0/problem-report"

	// ProblemReportTypeError is type for error problem report
	ProblemReportTypeError = "e"

	// ProblemReportTypeWarning is type for error problem report
	ProblemReportTypeWarning = "w"

	// ReportDescriptorTrust - Failed to achieve required trust.
	ReportDescriptorTrust = "trust"

	// ReportDescriptorTrustCrypto - Cryptographic operation failed.
	ReportDescriptorTrustCrypto = "trust.crypto"

	// ReportDescriptorTransport - Unable to transport data
	ReportDescriptorTransport = "xfer"

	// ReportDescriptorDID - DID is unusable
	ReportDescriptorDID = "did"

	// ReportDescriptorMsg - Bad message
	ReportDescriptorMsg = "msg"

	// ReportDescriptorMe - Internal error
	ReportDescriptorMe = "me"

	// ReportDescriptorReq - Circumstances don’t satisfy requirements. Request cannot be processed because circumstances has changed
	ReportDescriptorReq = "req"

	// ReportDescriptorReqTime - Failed to satisfy timing constraints.
	ReportDescriptorReqTime = "req.time"

	// ReportDescriptorLegal - Failed for legal reasons.
	ReportDescriptorLegal = "legal"
)

// ProblemReportMessage represent Iden3Message for problem report
type ProblemReportMessage struct {
	ID             string                    `json:"id"`
	Typ            iden3comm.MediaType       `json:"typ,omitempty"`
	Type           iden3comm.ProtocolMessage `json:"type"`
	ThreadID       string                    `json:"thid,omitempty"`
	ParentThreadID string                    `json:"pthid"`
	Ack            []string                  `json:"ack,omitempty"`

	Body ProblemReportMessageBody `json:"body,omitempty"`

	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

// ProblemReportMessageBody is struct the represents body for problem report
// Code is an error code. Example
// Comment is a human-readable description of the problem. Directly related to the error code.
// Args is a list of strings that can be used to replace placeholders in the error message.
// EscalateTo is a string that can be used to escalate the problem to a human operator. It can be an email
type ProblemReportMessageBody struct {
	Code       ProblemErrorCode `json:"code"`
	Comment    string           `json:"comment,omitempty"`
	Args       []string         `json:"args,omitempty"`
	EscalateTo string           `json:"escalate_to,omitempty"`
}

// ProblemErrorCode is a string  that represents an error code "e.p.xxxx.yyyy.zzzz"
type ProblemErrorCode string

// NewProblemReportErrorCode is a helper function to create a valid ProblemErrorCode
func NewProblemReportErrorCode(sorter, scope string, descriptors []string) (ProblemErrorCode, error) {
	if sorter != "e" && sorter != "w" {
		return "", errors.New("invalid sorter. allowed values [e:error, w:warning]")
	}
	if !isKebabCase(scope) {
		return "", errors.New("invalid scope. must be kebab-case")
	}
	if len(descriptors) == 0 {
		return "", errors.New("at least one descriptor is required")
	}
	for _, d := range descriptors {
		if !isKebabCase(d) {
			return "", errors.New("invalid descriptor. must be kebab-case")
		}
	}
	return ProblemErrorCode(sorter + "." + scope + "." + strings.Join(descriptors, ".")), nil
}

// ParseProblemErrorCode parses a string into a ProblemErrorCode. Useful to validate strings from external sources
func ParseProblemErrorCode(s string) (ProblemErrorCode, error) {
	parts := strings.Split(s, ".")
	if len(parts) < 3 {
		return "", errors.New("invalid error code. format sorter.scope.descriptors")
	}
	return NewProblemReportErrorCode(parts[0], parts[1], parts[2:])
}

func isKebabCase(s string) bool {
	for i, r := range s {
		if r == '-' {
			if i == 0 || i == len(s)-1 {
				return false
			}
			if s[i-1] == '-' {
				return false
			}
		}
	}
	return true
}
