// Package iden3comm defines core structures and intefaces for the messaging protocol
package iden3comm

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/pkg/errors"
)

// Packer converts message to encrypted or encoded form
type Packer interface {
	// Pack a payload of type ContentType in an Iden3 compliant format using the packer identity
	Pack(payload []byte, params PackerParams) ([]byte, error)
	// Unpack an envelope in Iden3 compliant format.
	Unpack(envelope []byte) (*BasicMessage, error)
	// MediaType returns content type of message
	MediaType() MediaType
}

// PackerParams mock interface for packer params
type PackerParams interface {
	Params()
}

// PackageManager is a registry of packers for iden3comm protocol
type PackageManager struct {
	packers map[MediaType]Packer
}

// NewPackageManager return new packager
func NewPackageManager() *PackageManager {
	return &PackageManager{packers: make(map[MediaType]Packer)}
}

// RegisterPackers adds new packers to packageManager
func (r *PackageManager) RegisterPackers(packers ...Packer) error {
	for _, p := range packers {
		_, ok := r.packers[p.MediaType()]
		if ok {
			return errors.Errorf("packer already registered %s", p.MediaType())
		}
		r.packers[p.MediaType()] = p
	}
	return nil
}

// Pack performs packing of message with a given mediatype
func (r *PackageManager) Pack(mediaType MediaType, payload []byte, params PackerParams) ([]byte, error) {

	p, ok := r.packers[mediaType]
	if !ok {
		return nil, errors.Errorf("packer for media type %s doesn't exist", mediaType)
	}

	envelope, err := p.Pack(payload, params)
	if err != nil {
		return nil, err
	}
	return envelope, nil
}

// Unpack returns iden3 message method from envelope
// if it's not valid or can't be decrypted error is returned
func (r *PackageManager) Unpack(envelope []byte) (*BasicMessage, MediaType, error) {
	safeEnvelope := strings.Trim(strings.TrimSpace(string(envelope)), "\"")
	mediaType, err := r.GetMediaType([]byte(safeEnvelope))
	if err != nil {
		return nil, "", err
	}

	msg, err := r.unpackSafeEnvelope(mediaType, []byte(safeEnvelope))
	if err != nil {
		return nil, mediaType, err
	}
	return msg, mediaType, nil
}

// UnpackWithType unpack envelop with target media type.
func (r *PackageManager) UnpackWithType(mediaType MediaType, envelope []byte) (*BasicMessage, error) {
	safeEnvelope := strings.Trim(strings.TrimSpace(string(envelope)), "\"")
	return r.unpackSafeEnvelope(mediaType, []byte(safeEnvelope))
}

func (r *PackageManager) unpackSafeEnvelope(mediaType MediaType, envelope []byte) (*BasicMessage, error) {
	p, ok := r.packers[mediaType]
	if !ok {
		return nil, errors.Errorf("packer for media type %s doesn't exist", mediaType)
	}

	// safeEnvelope can be rather base64 encoded or valid json
	msg, err := p.Unpack(envelope)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

type envelopeStub struct {
	Protected string `json:"protected"`
}
type headerStub struct {
	MediaType MediaType `json:"typ"`
}

// TrimDoubleQuoutes removes double quotes from message
func (r *PackageManager) TrimDoubleQuoutes(msg []byte) []byte {

	doubleQuote := []byte("\"")

	// packed message is base64 encoded and double-quoted.
	if bytes.HasPrefix(msg, doubleQuote) && bytes.HasSuffix(msg, doubleQuote) {
		msg = msg[1 : len(msg)-1]
	}
	return msg

}

// GetMediaType returns MediaType of envelope
func (r *PackageManager) GetMediaType(envelope []byte) (MediaType, error) {

	// try parse plain message

	var msg BasicMessage

	err := json.Unmarshal(envelope, &msg)
	if err == nil && msg.Typ != "" {
		return msg.Typ, nil
	}
	// we assume that it's not a plain message can continue to determine media type
	env := &envelopeStub{}

	var base64Header []byte

	if strings.HasPrefix(string(envelope), "{") { // full serialized
		err = json.Unmarshal(envelope, env)
		if err != nil {
			return "", fmt.Errorf("parse envelope: %w", err)
		}
		base64Header, err = base64.StdEncoding.DecodeString(env.Protected)
		if err != nil {
			return "", fmt.Errorf("parse envelope: %w", err)
		}
	} else {
		header := strings.Split(string(envelope), ".")[0]
		base64Header, err = base64.RawURLEncoding.DecodeString(header)
		if err != nil {
			return "", fmt.Errorf("parse base64 err: %w", err)
		}
	}

	header := &headerStub{}

	err = json.Unmarshal(base64Header, &header)
	if err != nil {
		return "", fmt.Errorf("parse header: %w", err)
	}

	return header.MediaType, nil
}
