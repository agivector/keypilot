/*
Description: Defines typed domain errors and storage sentinel errors.
Author: vectorshi
Created: 2026-11-25
*/
package keyregistry

import "errors"

var (
	ErrStorageNotFound = errors.New("storage resource not found")
	ErrStorageConflict = errors.New("storage resource already exists")
)

// DomainError describes a stable business error returned by the service layer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type DomainError struct {
	Code    APIErrorCode
	Message string
	Cause   error
}

// Error returns the human-readable domain error message.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - domainError: DomainError receiver.
//
// Returns:
//   - string: human-readable error message.
func (domainError *DomainError) Error() string {
	return domainError.Message
}

// Unwrap returns the underlying cause when one is available.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - domainError: DomainError receiver.
//
// Returns:
//   - error: underlying cause.
func (domainError *DomainError) Unwrap() error {
	return domainError.Cause
}

// NewDomainError creates a typed domain error.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - code: stable API error code.
//   - message: human-readable diagnostic message.
//   - cause: optional underlying error.
//
// Returns:
//   - *DomainError: constructed domain error.
func NewDomainError(code APIErrorCode, message string, cause error) *DomainError {
	return &DomainError{Code: code, Message: message, Cause: cause}
}
