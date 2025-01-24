package utils

import (
	core "github.com/iden3/go-iden3-core/v2"
)

const (
	// SubjectPositionIndex save subject in index part of claim. By default.
	// Deprecated: use verifiable.CredentialSubjectPositionIndex instead
	SubjectPositionIndex = "index"
	// SubjectPositionValue save subject in value part of claim.
	// Deprecated: use verifiable.CredentialSubjectPositionValue instead
	SubjectPositionValue = "value"

	// MerklizedRootPositionIndex merklized root is stored in index.
	// Deprecated: use verifiable.CredentialMerklizedRootPositionIndex instead
	MerklizedRootPositionIndex = "index"
	// MerklizedRootPositionValue merklized root is stored in value.
	// Deprecated: use verifiable.CredentialMerklizedRootPositionValue instead
	MerklizedRootPositionValue = "value"
	// MerklizedRootPositionNone merklized root is not stored in the claim. By Default.
	// Deprecated: use verifiable.CredentialMerklizedRootPositionNone instead
	MerklizedRootPositionNone = ""
)

// SwapEndianness swaps the endianness of the value encoded in buf. If buf is
// Big-Endian, the result will be Little-Endian and vice-versa.
func SwapEndianness(buf []byte) []byte {
	newBuf := make([]byte, len(buf))
	for i, b := range buf {
		newBuf[len(buf)-1-i] = b
	}
	return newBuf
}

// CreateSchemaHash computes schema hash from schemaID
func CreateSchemaHash(schemaID []byte) core.SchemaHash {
	var sHash core.SchemaHash
	h := Keccak256(schemaID)
	copy(sHash[:], h[len(h)-16:])
	return sHash
}
