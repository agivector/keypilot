/*
Description: Defines stable error values returned by the KeyPilot Go SDK.
Author: vectorshi
Created: 2026-11-25
*/
package keypilot

import "fmt"

// SDKError describes a verification, refresh, or configuration failure.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type SDKError struct {
	Code    SDKErrorCode
	Message string
	Cause   error
}

// Error returns the stable error code and diagnostic message.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - sdkError: SDKError receiver.
//
// Returns:
//   - string: formatted error text.
func (sdkError *SDKError) Error() string {
	if sdkError == nil {
		return ""
	}
	return fmt.Sprintf("keypilot sdk error code=%d: %s", sdkError.Code, sdkError.Message)
}

// Unwrap returns the lower-level cause when one is available.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - sdkError: SDKError receiver.
//
// Returns:
//   - error: wrapped cause or nil.
func (sdkError *SDKError) Unwrap() error {
	if sdkError == nil {
		return nil
	}
	return sdkError.Cause
}

// ErrorCode returns the stable SDK error code from an error.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - err: error returned by the SDK.
//
// Returns:
//   - SDKErrorCode: stable error code or INTERNAL_ERROR for unknown errors.
func ErrorCode(err error) SDKErrorCode {
	if sdkError, ok := err.(*SDKError); ok {
		return sdkError.Code
	}
	return SDKErrorInternal
}

// newSDKError creates an SDK error with a stable code.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - code: stable SDK error code.
//   - message: diagnostic message without sensitive key material.
//   - cause: optional lower-level error.
//
// Returns:
//   - *SDKError: constructed SDK error.
func newSDKError(code SDKErrorCode, message string, cause error) *SDKError {
	return &SDKError{Code: code, Message: message, Cause: cause}
}
