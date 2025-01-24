package verifiable

const (
	// DIDDocumentJSONSchema is a basic schema of did document
	DIDDocumentJSONSchema = `{
  "type": "object",
  "$defs": {
    "serviceEndpoint": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "serviceEndpoint": {
          "type": "string"
        },
        "metadata": {
          "type": "object"
        }
      },
      "required": [
        "id",
        "type",
        "serviceEndpoint"
      ]
    },
    "jsonWebKey": {
      "type": "object",
      "properties": {
        "alg": {
          "type": "string"
        },
        "crv": {
          "type": "string"
        },
        "e": {
          "type": "string"
        },
        "ext": {
          "type": "boolean"
        },
        "key_ops": {
          "type": "array",
          "items": {
            "type": "string"
          }
        },
        "kid": {
          "type": "string"
        },
        "kty": {
          "type": "string"
        },
        "n": {
          "type": "string"
        },
        "use": {
          "type": "string"
        },
        "x": {
          "type": "string"
        },
        "y": {
          "type": "string"
        }
      },
      "required": [
        "kty"
      ],
      "description": "Public parts of JSON web key"
    },
    "verificationMethod": {
      "type": "object",
      "properties": {
        "id": {
          "type": "string"
        },
        "type": {
          "type": "string"
        },
        "controller": {
          "type": "string"
        },
        "publicKeyBase58": {
          "type": "string"
        },
        "publicKeyBase64": {
          "type": "string"
        },
        "publicKeyJwk": {
          "$ref": "#/$defs/jsonWebKey"
        },
        "publicKeyHex": {
          "type": "string"
        },
        "publicKeyMultibase": {
          "type": "string"
        },
        "blockchainAccountId": {
          "type": "string"
        },
        "ethereumAddress": {
          "type": "string"
        },
        "stateContractAddress": {
          "type": "string"
        }
      },
      "required": [
        "id",
        "type",
        "controller"
      ]
    }
  },
  "properties": {
    "authentication": {
      "type": "array",
      "items": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "$ref": "#/$defs/verificationMethod"
          }
        ]
      }
    },
    "assertionMethod": {
      "type": "array",
      "items": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "$ref": "#/$defs/verificationMethod"
          }
        ]
      }
    },
    "keyAgreement": {
      "type": "array",
      "items": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "$ref": "#/$defs/verificationMethod"
          }
        ]
      }
    },
    "capabilityInvocation": {
      "type": "array",
      "items": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "$ref": "#/$defs/verificationMethod"
          }
        ]
      }
    },
    "capabilityDelegation": {
      "type": "array",
      "items": {
        "anyOf": [
          {
            "type": "string"
          },
          {
            "$ref": "#/$defs/verificationMethod"
          }
        ]
      }
    },
    "@context": {
      "anyOf": [
        {
          "type": "string",
          "const": "https://www.w3.org/ns/did/v1"
        },
        {
          "type": "string"
        },
        {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      ]
    },
    "id": {
      "type": "string"
    },
    "alsoKnownAs": {
      "type": "array",
      "items": {
        "type": "string"
      }
    },
    "controller": {
      "anyOf": [
        {
          "type": "string"
        },
        {
          "type": "array",
          "items": {
            "type": "string"
          }
        }
      ]
    },
    "verificationMethod": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/verificationMethod"
      }
    },
    "service": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/serviceEndpoint"
      }
    },
    "publicKey": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/verificationMethod"
      },
      "deprecated": true
    }
  },
  "required": [
    "id"
  ]
}`

	// AuthBJJJsonSchema is a basic schema of auth BJJ
	AuthBJJJsonSchema = `{
  "$schema": "http://json-schema.org/draft-07/schema#",
  "$metadata": {
    "uris": {
      "jsonLdContext": "https://schema.iden3.io/core/jsonld/auth.jsonld",
      "jsonSchema": "https://schema.iden3.io/core/json/auth.json"
    }
  },
  "type": "object",
  "required": [
    "@context",
    "id",
    "type",
    "issuanceDate",
    "credentialSubject",
    "credentialSchema",
    "credentialStatus",
    "issuer"
  ],
  "properties": {
    "@context": {
      "type": [
        "string",
        "array",
        "object"
      ]
    },
    "id": {
      "type": "string"
    },
    "type": {
      "type": [
        "string",
        "array"
      ],
      "items": {
        "type": "string"
      }
    },
    "issuer": {
      "type": [
        "string",
        "object"
      ],
      "format": "uri",
      "required": [
        "id"
      ],
      "properties": {
        "id": {
          "type": "string",
          "format": "uri"
        }
      }
    },
    "issuanceDate": {
      "type": "string",
      "format": "date-time"
    },
    "expirationDate": {
      "type": "string",
      "format": "date-time"
    },
    "credentialSchema": {
      "type": "object",
      "required": [
        "id",
        "type"
      ],
      "properties": {
        "id": {
          "type": "string",
          "format": "uri"
        },
        "type": {
          "type": "string"
        }
      }
    },
    "credentialSubject": {
      "type": "object",
      "required": [
        "x",
        "y"
      ],
      "properties": {
        "id": {
          "title": "Credential Subject ID",
          "type": "string",
          "format": "uri"
        },
        "x": {
          "type": "string"
        },
        "y": {
          "type": "string"
        }
      }
    }
  }
}`

	// AuthBJJJsonLDSchema is a JSON-LD schema of auth BJJ
	AuthBJJJsonLDSchema = `{
  "@context": [{
    "@version": 1.1,
    "@protected": true,
    "id": "@id",
    "type": "@type",
    "AuthBJJCredential": {
      "@id": "https://schema.iden3.io/core/jsonld/auth.jsonld#AuthBJJCredential",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "iden3_serialization": "iden3:v1:slotIndexA=x&slotIndexB=y",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "auth-vocab": "https://schema.iden3.io/core/vocab/auth.md#",
        "x": {
          "@id": "auth-vocab:x",
          "@type": "xsd:positiveInteger"
        },
        "y": {
          "@id": "auth-vocab:y",
          "@type": "xsd:positiveInteger"
        }
      }
    },
    "Iden3StateInfo2023": {
      "@id": "https://schema.iden3.io/core/jsonld/auth.jsonld#Iden3StateInfo2023",
      "@context": {
        "@version": 1.1,
        "@protected": true,
        "id": "@id",
        "type": "@type",
        "xsd": "http://www.w3.org/2001/XMLSchema#",
        "@vocab": "https://schema.iden3.io/core/vocab/state-info.md#",
        "@propagate": true,
        "stateContractAddress": {
          "@id": "stateContractAddress",
          "@type": "xsd:string"
        },
        "published": {
          "@id": "published",
          "@type": "xsd:boolean"
        },
        "info": {
          "@id": "info",
          "@type": "@id",
          "@context": {
            "@protected": true,
            "id": {
              "@id": "id",
              "@type": "xsd:string"
            },
            "state": {
              "@id": "state",
              "@type": "xsd:string"
            },
            "replacedByState": {
              "@id": "replacedByState",
              "@type": "xsd:string"
            },
            "createdAtTimestamp": {
              "@id": "createdAtTimestamp",
              "@type": "xsd:string"
            },
            "replacedAtTimestamp": {
              "@id": "replacedAtTimestamp",
              "@type": "xsd:string"
            },
            "createdAtBlock": {
              "@id": "createdAtBlock",
              "@type": "xsd:string"
            },
            "replacedAtBlock": {
              "@id": "replacedAtBlock",
              "@type": "xsd:string"
            }
          }
        },
        "global": {
          "@id": "global",
          "@type": "@id",
          "@context": {
            "@protected": true,
            "sec": "https://w3id.org/security#",
            "root": {
              "@id": "root",
              "@type": "xsd:string"
            },
            "replacedByRoot": {
              "@id": "replacedByRoot",
              "@type": "xsd:string"
            },
            "createdAtTimestamp": {
              "@id": "createdAtTimestamp",
              "@type": "xsd:string"
            },
            "replacedAtTimestamp": {
              "@id": "replacedAtTimestamp",
              "@type": "xsd:string"
            },
            "createdAtBlock": {
              "@id": "createdAtBlock",
              "@type": "xsd:string"
            },
            "replacedAtBlock": {
              "@id": "replacedAtBlock",
              "@type": "xsd:string"
            },
            "proof": {
              "@id": "sec:proof",
              "@type": "@id",
              "@container": "@graph"
            }
          }
        }
      }
    }
  }]
}`
)
