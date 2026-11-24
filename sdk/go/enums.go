/*
Description: Defines stable numeric enums exposed by the KeyPilot Go SDK.
Author: vectorshi
Created: 2026-11-25
*/
package keypilot

// CryptoAlgorithm identifies a supported signature verification algorithm.
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

// IsSupported reports whether the SDK implements the algorithm.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - algorithm: CryptoAlgorithm receiver to validate.
//
// Returns:
//   - bool: true when the algorithm is implemented.
func (algorithm CryptoAlgorithm) IsSupported() bool {
	return algorithm == CryptoAlgorithmRS256 || algorithm == CryptoAlgorithmPS256
}

// FailureMode controls how stale cached keys are handled when JWKS refresh fails.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type FailureMode int

const (
	FailureModeStrict    FailureMode = 1
	FailureModeAvailable FailureMode = 2
)

// IsValid reports whether the failure mode is defined by the SDK contract.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - mode: FailureMode receiver to validate.
//
// Returns:
//   - bool: true when the failure mode is supported.
func (mode FailureMode) IsValid() bool {
	return mode == FailureModeStrict || mode == FailureModeAvailable
}

// SDKErrorCode identifies a stable SDK failure category.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type SDKErrorCode int

const (
	SDKErrorInvalidArgument     SDKErrorCode = 6001
	SDKErrorAlgorithmNotAllowed SDKErrorCode = 6002
	SDKErrorKeyNotFound         SDKErrorCode = 6003
	SDKErrorKeyInvalid          SDKErrorCode = 6004
	SDKErrorSignatureInvalid    SDKErrorCode = 6005
	SDKErrorJWKSUnavailable     SDKErrorCode = 6006
	SDKErrorJWKSInvalidResponse SDKErrorCode = 6007
	SDKErrorCacheExpired        SDKErrorCode = 6008
	SDKErrorConfiguration       SDKErrorCode = 6009
	SDKErrorInternal            SDKErrorCode = 6999
)
