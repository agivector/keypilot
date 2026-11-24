/*
Description: Defines KeyPilot issuer, verification key, JWK, and audit models.
Author: vectorshi
Created: 2026-11-25
*/
package keyregistry

import "time"

// Issuer describes a trusted signature issuer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type Issuer struct {
	Issuer      string    `json:"issuer"`
	DisplayName string    `json:"displayName"`
	Description string    `json:"description,omitempty"`
	CreateTime  time.Time `json:"create_time"`
	UpdateTime  time.Time `json:"update_time"`
}

// RSAPublicJWK describes the supported public fields of an RSA JWK.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type RSAPublicJWK struct {
	KeyType  string `json:"kty"`
	KeyID    string `json:"kid"`
	Use      string `json:"use"`
	Alg      string `json:"alg"`
	Modulus  string `json:"n"`
	Exponent string `json:"e"`
}

// VerificationKey describes a managed public verification key.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type VerificationKey struct {
	Issuer       string          `json:"issuer"`
	KeyID        string          `json:"kid"`
	KeyType      KeyType         `json:"key_type"`
	Purpose      KeyPurpose      `json:"purpose"`
	Algorithm    CryptoAlgorithm `json:"algorithm"`
	Status       KeyStatus       `json:"status"`
	JWK          RSAPublicJWK    `json:"jwk"`
	Description  string          `json:"description,omitempty"`
	CreateTime   time.Time       `json:"create_time"`
	UpdateTime   time.Time       `json:"update_time"`
	ActivateTime *time.Time      `json:"activate_time,omitempty"`
	RetireTime   *time.Time      `json:"retire_time,omitempty"`
	ArchiveTime  *time.Time      `json:"archive_time,omitempty"`
	RevokeTime   *time.Time      `json:"revoke_time,omitempty"`
	RevokeReason string          `json:"revokedReason,omitempty"`
}

// AuditContext describes the authenticated administration request metadata copied into audit records.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type AuditContext struct {
	RequestID string
	Actor     string
	ClientIP  string
	UserAgent string
}

// AuditRecord describes a persisted administration audit event.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type AuditRecord struct {
	RequestID    string       `json:"requestId"`
	Actor        string       `json:"actor"`
	ClientIP     string       `json:"clientIp,omitempty"`
	UserAgent    string       `json:"userAgent,omitempty"`
	Action       AuditAction  `json:"action"`
	Issuer       string       `json:"issuer,omitempty"`
	KeyID        string       `json:"kid,omitempty"`
	Result       AuditResult  `json:"result"`
	BeforeStatus KeyStatus    `json:"beforeStatus,omitempty"`
	AfterStatus  KeyStatus    `json:"afterStatus,omitempty"`
	ErrorCode    APIErrorCode `json:"errorCode,omitempty"`
	Reason       string       `json:"reason,omitempty"`
	CreateTime   time.Time    `json:"create_time"`
}

// JWKSet describes a standard JSON Web Key Set response.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type JWKSet struct {
	Keys []RSAPublicJWK `json:"keys"`
}
