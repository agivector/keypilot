/*
Description: Defines stable numeric enums used by the KeyPilot domain.
Author: vectorshi
Created: 2026-11-25
*/
package keyregistry

// KeyStatus describes the lifecycle state of a managed verification key.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type KeyStatus int

const (
	KeyStatusPreActive KeyStatus = 1
	KeyStatusActive    KeyStatus = 2
	KeyStatusRetired   KeyStatus = 3
	KeyStatusArchived  KeyStatus = 4
	KeyStatusRevoked   KeyStatus = 5
)

// IsValid reports whether the key status is defined by the current specification.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - status: KeyStatus receiver to validate.
//
// Returns:
//   - bool: true when the value is a supported key status.
func (status KeyStatus) IsValid() bool {
	return status >= KeyStatusPreActive && status <= KeyStatusRevoked
}

// CryptoAlgorithm describes a stable numeric cryptographic algorithm identifier.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type CryptoAlgorithm int

const (
	CryptoAlgorithmRS256 CryptoAlgorithm = 1001
	CryptoAlgorithmPS256 CryptoAlgorithm = 1002
)

// IsSupported reports whether the algorithm is implemented in the first release.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - algorithm: CryptoAlgorithm receiver to validate.
//
// Returns:
//   - bool: true when the algorithm is currently supported.
func (algorithm CryptoAlgorithm) IsSupported() bool {
	return algorithm == CryptoAlgorithmRS256 || algorithm == CryptoAlgorithmPS256
}

// KeyType describes the cryptographic key family.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type KeyType int

const (
	KeyTypeRSA KeyType = 1
	KeyTypeSM2 KeyType = 2
	KeyTypeSM4 KeyType = 3
)

// KeyPurpose describes the intended cryptographic capability of a managed key.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type KeyPurpose int

const (
	KeyPurposeSignVerify     KeyPurpose = 1
	KeyPurposeEncryptDecrypt KeyPurpose = 2
)

// APIErrorCode describes a stable numeric API error identifier.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type APIErrorCode int

const (
	APIErrorValidation           APIErrorCode = 1001
	APIErrorInvalidJWK           APIErrorCode = 1002
	APIErrorPrivateKeyNotAllowed APIErrorCode = 1003
	APIErrorAlgorithmNotAllowed  APIErrorCode = 1004
	APIErrorUnauthorized         APIErrorCode = 2001
	APIErrorIssuerNotFound       APIErrorCode = 3001
	APIErrorKeyNotFound          APIErrorCode = 3002
	APIErrorIssuerAlreadyExists  APIErrorCode = 4001
	APIErrorKeyAlreadyExists     APIErrorCode = 4002
	APIErrorInvalidKeyTransition APIErrorCode = 4003
	APIErrorInternal             APIErrorCode = 5001
	APIErrorStorageUnavailable   APIErrorCode = 5002
)

// AuditAction describes a stable numeric administration action identifier.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type AuditAction int

const (
	AuditActionCreateIssuer   AuditAction = 1
	AuditActionImportKey      AuditAction = 2
	AuditActionUpdateKeyState AuditAction = 3
	AuditActionAuthentication AuditAction = 4
)

// AuditResult describes the outcome of an administration action.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type AuditResult int

const (
	AuditResultSuccess AuditResult = 1
	AuditResultFailure AuditResult = 2
)
