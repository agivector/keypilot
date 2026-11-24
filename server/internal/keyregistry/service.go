/*
Description: Implements issuer, key lifecycle, validation, and JWKS business rules.
Author: vectorshi
Created: 2026-11-25
*/
package keyregistry

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"regexp"
	"sort"
	"strings"
	"time"
)

var issuerPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Service coordinates KeyPilot business rules with persistent storage.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type Service struct {
	store Store
	now   func() time.Time
}

// NewService creates a key registry service.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - store: persistence implementation used by the service.
//   - now: optional UTC clock function; time.Now is used when nil.
//
// Returns:
//   - *Service: initialized key registry service.
func NewService(store Store, now func() time.Time) *Service {
	if now == nil {
		now = time.Now
	}
	return &Service{store: store, now: now}
}

// CreateIssuer validates and persists a new issuer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - requestID: request correlation identifier.
//   - issuer: stable issuer identifier.
//   - displayName: human-readable issuer name.
//   - description: optional issuer description.
//
// Returns:
//   - Issuer: persisted issuer.
//   - error: validation, conflict, or storage error.
func (service *Service) CreateIssuer(ctx context.Context, requestID string, issuer string, displayName string, description string) (Issuer, error) {
	issuer = strings.TrimSpace(issuer)
	displayName = strings.TrimSpace(displayName)
	description = strings.TrimSpace(description)
	if !issuerPattern.MatchString(issuer) || displayName == "" || len(displayName) > 128 || len(description) > 500 {
		return Issuer{}, NewDomainError(APIErrorValidation, "issuer request is invalid", nil)
	}

	now := service.now().UTC()
	record := Issuer{Issuer: issuer, DisplayName: displayName, Description: description, CreateTime: now, UpdateTime: now}
	audit := AuditRecord{RequestID: requestID, Action: AuditActionCreateIssuer, Issuer: issuer, Result: AuditResultSuccess, CreateTime: now}
	if err := service.store.CreateIssuer(ctx, record, audit); err != nil {
		if errors.Is(err, ErrStorageConflict) {
			return Issuer{}, NewDomainError(APIErrorIssuerAlreadyExists, "issuer already exists", err)
		}
		return Issuer{}, NewDomainError(APIErrorStorageUnavailable, "issuer could not be stored", err)
	}
	return record, nil
}

// ListIssuers returns all issuers in stable identifier order.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//
// Returns:
//   - []Issuer: issuer list.
//   - error: storage error.
func (service *Service) ListIssuers(ctx context.Context) ([]Issuer, error) {
	issuers, err := service.store.ListIssuers(ctx)
	if err != nil {
		return nil, NewDomainError(APIErrorStorageUnavailable, "issuers could not be loaded", err)
	}
	sort.Slice(issuers, func(left int, right int) bool { return issuers[left].Issuer < issuers[right].Issuer })
	return issuers, nil
}

// GetIssuer returns one issuer by stable identifier.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: stable issuer identifier.
//
// Returns:
//   - Issuer: requested issuer.
//   - error: not-found or storage error.
func (service *Service) GetIssuer(ctx context.Context, issuer string) (Issuer, error) {
	record, err := service.store.GetIssuer(ctx, issuer)
	if errors.Is(err, ErrStorageNotFound) {
		return Issuer{}, NewDomainError(APIErrorIssuerNotFound, "issuer was not found", err)
	}
	if err != nil {
		return Issuer{}, NewDomainError(APIErrorStorageUnavailable, "issuer could not be loaded", err)
	}
	return record, nil
}

// ImportKey validates and persists a new RSA verification key in PRE_ACTIVE state.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - requestID: request correlation identifier.
//   - issuer: owner issuer identifier.
//   - jwk: RSA public JWK.
//   - description: optional key description.
//
// Returns:
//   - VerificationKey: persisted verification key.
//   - error: validation, conflict, not-found, or storage error.
func (service *Service) ImportKey(ctx context.Context, requestID string, issuer string, jwk RSAPublicJWK, description string) (VerificationKey, error) {
	if _, err := service.GetIssuer(ctx, issuer); err != nil {
		return VerificationKey{}, err
	}
	algorithm, err := validateJWK(jwk)
	if err != nil {
		return VerificationKey{}, err
	}
	if len(description) > 500 {
		return VerificationKey{}, NewDomainError(APIErrorValidation, "key description is too long", nil)
	}

	now := service.now().UTC()
	key := VerificationKey{
		Issuer: issuer, KeyID: jwk.KeyID, KeyType: KeyTypeRSA, Purpose: KeyPurposeSignVerify,
		Algorithm: algorithm, Status: KeyStatusPreActive,
		JWK: jwk, Description: strings.TrimSpace(description), CreateTime: now, UpdateTime: now,
	}
	audit := AuditRecord{RequestID: requestID, Action: AuditActionImportKey, Issuer: issuer, KeyID: jwk.KeyID, Result: AuditResultSuccess, CreateTime: now}
	if err := service.store.CreateKey(ctx, key, audit); err != nil {
		if errors.Is(err, ErrStorageConflict) {
			return VerificationKey{}, NewDomainError(APIErrorKeyAlreadyExists, "verification key already exists", err)
		}
		return VerificationKey{}, NewDomainError(APIErrorStorageUnavailable, "verification key could not be stored", err)
	}
	return key, nil
}

// ListKeys returns all keys for an issuer in stable key identifier order.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: owner issuer identifier.
//
// Returns:
//   - []VerificationKey: verification key list.
//   - error: not-found or storage error.
func (service *Service) ListKeys(ctx context.Context, issuer string) ([]VerificationKey, error) {
	if _, err := service.GetIssuer(ctx, issuer); err != nil {
		return nil, err
	}
	keys, err := service.store.ListKeys(ctx, issuer)
	if err != nil {
		return nil, NewDomainError(APIErrorStorageUnavailable, "verification keys could not be loaded", err)
	}
	sort.Slice(keys, func(left int, right int) bool { return keys[left].KeyID < keys[right].KeyID })
	return keys, nil
}

// GetKey returns one verification key.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: owner issuer identifier.
//   - keyID: key identifier within the issuer.
//
// Returns:
//   - VerificationKey: requested key.
//   - error: not-found or storage error.
func (service *Service) GetKey(ctx context.Context, issuer string, keyID string) (VerificationKey, error) {
	key, err := service.store.GetKey(ctx, issuer, keyID)
	if errors.Is(err, ErrStorageNotFound) {
		return VerificationKey{}, NewDomainError(APIErrorKeyNotFound, "verification key was not found", err)
	}
	if err != nil {
		return VerificationKey{}, NewDomainError(APIErrorStorageUnavailable, "verification key could not be loaded", err)
	}
	return key, nil
}

// UpdateKeyStatus applies a valid lifecycle transition and persists an audit record.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - requestID: request correlation identifier.
//   - issuer: owner issuer identifier.
//   - keyID: key identifier within the issuer.
//   - targetStatus: requested numeric key status.
//   - reason: optional transition reason; required for REVOKED.
//
// Returns:
//   - VerificationKey: updated key.
//   - error: validation, transition, not-found, or storage error.
func (service *Service) UpdateKeyStatus(ctx context.Context, requestID string, issuer string, keyID string, targetStatus KeyStatus, reason string) (VerificationKey, error) {
	if !targetStatus.IsValid() || targetStatus == KeyStatusPreActive {
		return VerificationKey{}, NewDomainError(APIErrorValidation, "target key status is invalid", nil)
	}
	key, err := service.GetKey(ctx, issuer, keyID)
	if err != nil {
		return VerificationKey{}, err
	}
	reason = strings.TrimSpace(reason)
	if key.Status == targetStatus {
		return key, nil
	}
	if targetStatus == KeyStatusRevoked && reason == "" {
		return VerificationKey{}, NewDomainError(APIErrorValidation, "revoke reason is required", nil)
	}
	if !canTransition(key.Status, targetStatus) {
		return VerificationKey{}, NewDomainError(APIErrorInvalidKeyTransition, "key status transition is not allowed", nil)
	}

	now := service.now().UTC()
	key.Status = targetStatus
	key.UpdateTime = now
	switch targetStatus {
	case KeyStatusActive:
		if key.ActivateTime == nil {
			key.ActivateTime = &now
		}
	case KeyStatusRetired:
		key.RetireTime = &now
	case KeyStatusArchived:
		key.ArchiveTime = &now
	case KeyStatusRevoked:
		key.RevokeTime = &now
		key.RevokeReason = reason
	}

	audit := AuditRecord{RequestID: requestID, Action: AuditActionUpdateKeyState, Issuer: issuer, KeyID: keyID, Result: AuditResultSuccess, Reason: reason, CreateTime: now}
	if err := service.store.UpdateKey(ctx, key, audit); err != nil {
		return VerificationKey{}, NewDomainError(APIErrorStorageUnavailable, "verification key could not be updated", err)
	}
	return key, nil
}

// GetJWKSet returns the currently published public keys for an issuer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: owner issuer identifier.
//
// Returns:
//   - JWKSet: stable key identifier ordered JWK Set.
//   - error: not-found or storage error.
func (service *Service) GetJWKSet(ctx context.Context, issuer string) (JWKSet, error) {
	keys, err := service.ListKeys(ctx, issuer)
	if err != nil {
		return JWKSet{}, err
	}
	result := JWKSet{Keys: make([]RSAPublicJWK, 0, len(keys))}
	for _, key := range keys {
		if key.Status == KeyStatusPreActive || key.Status == KeyStatusActive || key.Status == KeyStatusRetired {
			result.Keys = append(result.Keys, key.JWK)
		}
	}
	return result, nil
}

// canTransition reports whether a key lifecycle transition is allowed.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - currentStatus: current key status.
//   - targetStatus: requested key status.
//
// Returns:
//   - bool: true when the transition is allowed.
func canTransition(currentStatus KeyStatus, targetStatus KeyStatus) bool {
	switch currentStatus {
	case KeyStatusPreActive:
		return targetStatus == KeyStatusActive || targetStatus == KeyStatusRevoked
	case KeyStatusActive:
		return targetStatus == KeyStatusRetired || targetStatus == KeyStatusRevoked
	case KeyStatusRetired:
		return targetStatus == KeyStatusArchived || targetStatus == KeyStatusRevoked
	case KeyStatusArchived:
		return targetStatus == KeyStatusRevoked
	default:
		return false
	}
}

// validateJWK validates an RSA public JWK and maps its standard algorithm string to a numeric enum.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - jwk: RSA public JWK to validate.
//
// Returns:
//   - CryptoAlgorithm: mapped numeric crypto algorithm.
//   - error: invalid JWK or unsupported algorithm error.
func validateJWK(jwk RSAPublicJWK) (CryptoAlgorithm, error) {
	if jwk.KeyType != "RSA" || jwk.Use != "sig" || strings.TrimSpace(jwk.KeyID) == "" || len(jwk.KeyID) > 128 {
		return 0, NewDomainError(APIErrorInvalidJWK, "RSA public JWK fields are invalid", nil)
	}
	algorithm := CryptoAlgorithm(0)
	switch jwk.Alg {
	case "RS256":
		algorithm = CryptoAlgorithmRS256
	case "PS256":
		algorithm = CryptoAlgorithmPS256
	default:
		return 0, NewDomainError(APIErrorAlgorithmNotAllowed, "JWK algorithm is not allowed", nil)
	}
	if _, err := rsaPublicKey(jwk); err != nil {
		return 0, NewDomainError(APIErrorInvalidJWK, "RSA public JWK modulus or exponent is invalid", err)
	}
	return algorithm, nil
}

// rsaPublicKey converts a validated RSA JWK into an rsa.PublicKey.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - jwk: RSA public JWK.
//
// Returns:
//   - *rsa.PublicKey: parsed RSA public key.
//   - error: base64url or exponent parsing error.
func rsaPublicKey(jwk RSAPublicJWK) (*rsa.PublicKey, error) {
	modulusBytes, err := base64.RawURLEncoding.DecodeString(jwk.Modulus)
	if err != nil || len(modulusBytes) == 0 {
		return nil, errors.New("invalid modulus")
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.Exponent)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return nil, errors.New("invalid exponent")
	}
	exponent := 0
	for _, value := range exponentBytes {
		exponent = exponent<<8 | int(value)
	}
	if exponent < 3 || exponent%2 == 0 {
		return nil, errors.New("invalid exponent")
	}
	publicKey := &rsa.PublicKey{N: new(big.Int).SetBytes(modulusBytes), E: exponent}
	if publicKey.N.BitLen() < 2048 {
		return nil, errors.New("RSA modulus must be at least 2048 bits")
	}
	return publicKey, nil
}
