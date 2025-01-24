package verifiable

//nolint:gosec //reason: no need for security
const (

	// TypeW3CVerifiableCredential is of the w3c verifiable credential standard
	TypeW3CVerifiableCredential = "VerifiableCredential"

	// JSONLDSchemaIden3Credential is a schema for context with W3CCredential type
	JSONLDSchemaIden3Credential = "https://schema.iden3.io/core/jsonld/iden3proofs.jsonld"

	// JSONLDSchemaW3CCredential2018 is a schema for context with VerifiableCredential type
	JSONLDSchemaW3CCredential2018 = "https://www.w3.org/2018/credentials/v1"

	// JSONLDSchemaIden3DisplayMethod is a schema for context with Display method type
	JSONLDSchemaIden3DisplayMethod = "https://schema.iden3.io/core/jsonld/displayMethod.jsonld"

	// JSONLDSchemaIden3AuthBJJCredential is a schema for context with AuthBJJCredential type
	JSONLDSchemaIden3AuthBJJCredential = "https://schema.iden3.io/core/jsonld/auth.jsonld"

	JSONSchemaIden3AuthBJJCredential = "https://schema.iden3.io/core/json/auth.json"

	// SparseMerkleTreeProof is CredentialStatusType for standard MTP result handlers
	SparseMerkleTreeProof CredentialStatusType = "SparseMerkleTreeProof"

	// Iden3ReverseSparseMerkleTreeProof is CredentialStatusType  for reverse iden3 algorithm
	Iden3ReverseSparseMerkleTreeProof CredentialStatusType = "Iden3ReverseSparseMerkleTreeProof"

	// JSONSchemaValidator2018 JSON schema for verification of W3CCredential
	// Deprecated: https://www.w3.org/2018/credentials/#JsonSchemaValidator2018
	JSONSchemaValidator2018 = "JsonSchemaValidator2018"

	// JSONSchema2023 JSON schema for verification of W3CCredential (https://www.w3.org/TR/vc-json-schema/#jsonschema2023)
	JSONSchema2023 = "JsonSchema2023"

	// BJJSignatureProofType is a proof type for BJJ signature proofs
	BJJSignatureProofType ProofType = "BJJSignature2021"

	// Iden3SparseMerkleProofType is a proof type for MTP proofs with iden3 metadata
	//
	// Deprecated: Iden3SparseMerkleProofType is not correct semantically and replaced by Iden3SparseMerkleTreeProofType
	Iden3SparseMerkleProofType ProofType = "Iden3SparseMerkleProof"

	// Iden3SparseMerkleTreeProofType is a proof type for MTP proofs with iden3 metadata. Context is defined here: https://schema.iden3.io/core/jsonld/iden3proofs.jsonld
	Iden3SparseMerkleTreeProofType ProofType = "Iden3SparseMerkleTreeProof"

	// SparseMerkleTreeProofType ia a standard SMT proof type
	SparseMerkleTreeProofType ProofType = "SparseMerkleTreeProof"

	// ProofPurposeAuthentication defines a proof for authentication
	ProofPurposeAuthentication ProofPurpose = "Authentication"

	// Iden3CommServiceType is service type for iden3comm protocol
	Iden3CommServiceType = "iden3-communication"

	// PushNotificationServiceType is service type for delivering push notifications to identity
	PushNotificationServiceType = "push-notification"

	// Iden3MobileServiceType is service type for mobile function invoke to reach user agent in iden3 protocol
	Iden3MobileServiceType = "Iden3MobileServiceV1"

	// Iden3WebServiceType is service type for web redirects as a way to reach user agent in iden3 protocol
	Iden3WebServiceType = "Iden3WebRedirectServiceV1"

	// CredentialMerklizedRootPositionIndex is merklized root position of W3CCredential in the IndexDataSlotA (core claim)
	CredentialMerklizedRootPositionIndex = "index"

	// CredentialMerklizedRootPositionValue is merklized root position of W3CCredential in the ValueDataSlotA (core claim)
	CredentialMerklizedRootPositionValue = "value"

	// CredentialMerklizedRootPositionNone is for non-merklized W3CCredential
	CredentialMerklizedRootPositionNone = ""

	// CredentialSubjectPositionIndex is subject position of W3CCredential in index (core claim)
	CredentialSubjectPositionIndex = "index"

	// CredentialSubjectPositionValue is subject position of W3CCredential in value (core claim)
	CredentialSubjectPositionValue = "value"

	// CredentialSubjectRootPositionValue is subject position of W3CCredential in value (core claim)
	// Deprecated: use CredentialSubjectPositionValue instead
	CredentialSubjectRootPositionValue = "value"

	// Iden3commRevocationStatusV1 is CredentialStatusType for iden3comm revocation status
	Iden3commRevocationStatusV1 CredentialStatusType = "Iden3commRevocationStatusV1.0"

	// Iden3OnсhainSparseMerkleTreeProof2023 is a proof type for MTP proofs with iden3 metadata from blockchain
	Iden3OnchainSparseMerkleTreeProof2023 CredentialStatusType = "Iden3OnchainSparseMerkleTreeProof2023"

	// Iden3RefreshService2023 is the type of refresh service
	Iden3RefreshService2023 RefreshServiceType = "Iden3RefreshService2023"

	// Iden3BasicDisplayMethodV1 is the type fof basic display method
	Iden3BasicDisplayMethodV1 DisplayMethodType = "Iden3BasicDisplayMethodV1"
)
