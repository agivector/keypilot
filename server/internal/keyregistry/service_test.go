/*
Description: Tests key registry validation, lifecycle transitions, and JWKS publication rules.
Author: vectorshi
Created: 2026-11-25
*/
package keyregistry

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"
)

// memoryStore provides deterministic in-memory persistence for service unit tests.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type memoryStore struct {
	issuers map[string]Issuer
	keys    map[string]map[string]VerificationKey
	audits  []AuditRecord
}

// newMemoryStore creates an initialized test store.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns:
//   - *memoryStore: initialized test store.
func newMemoryStore() *memoryStore {
	return &memoryStore{issuers: make(map[string]Issuer), keys: make(map[string]map[string]VerificationKey), audits: make([]AuditRecord, 0)}
}

// CreateIssuer persists an issuer for service tests.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: issuer to persist.
//   - audit: ignored test audit record.
//
// Returns:
//   - error: conflict or cancellation error.
func (store *memoryStore) CreateIssuer(ctx context.Context, issuer Issuer, audit AuditRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, exists := store.issuers[issuer.Issuer]; exists {
		return ErrStorageConflict
	}
	store.issuers[issuer.Issuer] = issuer
	store.audits = append(store.audits, audit)
	return nil
}

// ListIssuers returns all test issuers.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//
// Returns:
//   - []Issuer: issuer list.
//   - error: cancellation error.
func (store *memoryStore) ListIssuers(ctx context.Context) ([]Issuer, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]Issuer, 0, len(store.issuers))
	for _, issuer := range store.issuers {
		result = append(result, issuer)
	}
	return result, nil
}

// GetIssuer returns one test issuer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: issuer identifier.
//
// Returns:
//   - Issuer: issuer record.
//   - error: not-found or cancellation error.
func (store *memoryStore) GetIssuer(ctx context.Context, issuer string) (Issuer, error) {
	if err := ctx.Err(); err != nil {
		return Issuer{}, err
	}
	record, exists := store.issuers[issuer]
	if !exists {
		return Issuer{}, ErrStorageNotFound
	}
	return record, nil
}

// CreateKey persists a test verification key.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - key: key to persist.
//   - audit: ignored test audit record.
//
// Returns:
//   - error: conflict or cancellation error.
func (store *memoryStore) CreateKey(ctx context.Context, key VerificationKey, audit AuditRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if store.keys[key.Issuer] == nil {
		store.keys[key.Issuer] = make(map[string]VerificationKey)
	}
	if _, exists := store.keys[key.Issuer][key.KeyID]; exists {
		return ErrStorageConflict
	}
	store.keys[key.Issuer][key.KeyID] = key
	store.audits = append(store.audits, audit)
	return nil
}

// ListKeys returns all test keys for an issuer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: issuer identifier.
//
// Returns:
//   - []VerificationKey: key list.
//   - error: cancellation error.
func (store *memoryStore) ListKeys(ctx context.Context, issuer string) ([]VerificationKey, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	result := make([]VerificationKey, 0, len(store.keys[issuer]))
	for _, key := range store.keys[issuer] {
		result = append(result, key)
	}
	return result, nil
}

// GetKey returns one test key.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: issuer identifier.
//   - keyID: key identifier.
//
// Returns:
//   - VerificationKey: key record.
//   - error: not-found or cancellation error.
func (store *memoryStore) GetKey(ctx context.Context, issuer string, keyID string) (VerificationKey, error) {
	if err := ctx.Err(); err != nil {
		return VerificationKey{}, err
	}
	key, exists := store.keys[issuer][keyID]
	if !exists {
		return VerificationKey{}, ErrStorageNotFound
	}
	return key, nil
}

// UpdateKey replaces one test key.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - key: updated key.
//   - audit: ignored test audit record.
//
// Returns:
//   - error: not-found or cancellation error.
func (store *memoryStore) UpdateKey(ctx context.Context, key VerificationKey, audit AuditRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, exists := store.keys[key.Issuer][key.KeyID]; !exists {
		return ErrStorageNotFound
	}
	store.keys[key.Issuer][key.KeyID] = key
	store.audits = append(store.audits, audit)
	return nil
}

// AppendAudit persists a standalone test audit record.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - audit: audit record to persist.
//
// Returns:
//   - error: cancellation error.
func (store *memoryStore) AppendAudit(ctx context.Context, audit AuditRecord) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	store.audits = append(store.audits, audit)
	return nil
}

// ListAudits returns all test audit records.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//
// Returns:
//   - []AuditRecord: copied audit records.
//   - error: cancellation error.
func (store *memoryStore) ListAudits(ctx context.Context) ([]AuditRecord, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]AuditRecord(nil), store.audits...), nil
}

// TestServiceLifecycleAndJWKS verifies valid lifecycle transitions and JWKS visibility.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestServiceLifecycleAndJWKS(testingContext *testing.T) {
	testingContext.Parallel()
	fixedTime := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	service := NewService(newMemoryStore(), func() time.Time { return fixedTime })
	ctx := context.Background()

	auditContext := AuditContext{RequestID: "request-1", Actor: "security-operator", ClientIP: "127.0.0.1"}
	if _, err := service.CreateIssuer(ctx, auditContext, "payment-service", "Payment Service", ""); err != nil {
		testingContext.Fatalf("create issuer: %v", err)
	}
	jwk := testJWK(testingContext, "payment-2026-01", "PS256")
	auditContext.RequestID = "request-2"
	key, err := service.ImportKey(ctx, auditContext, "payment-service", jwk, "rotation key")
	if err != nil {
		testingContext.Fatalf("import key: %v", err)
	}
	if key.Status != KeyStatusPreActive || key.KeyType != KeyTypeRSA || key.Purpose != KeyPurposeSignVerify || key.Algorithm != CryptoAlgorithmPS256 {
		testingContext.Fatalf("unexpected imported key: status=%d key_type=%d purpose=%d algorithm=%d", key.Status, key.KeyType, key.Purpose, key.Algorithm)
	}

	for _, targetStatus := range []KeyStatus{KeyStatusActive, KeyStatusRetired} {
		auditContext.RequestID = "request-3"
		key, err = service.UpdateKeyStatus(ctx, auditContext, "payment-service", key.KeyID, targetStatus, "")
		if err != nil {
			testingContext.Fatalf("update status %d: %v", targetStatus, err)
		}
	}
	jwkSet, err := service.GetJWKSet(ctx, "payment-service")
	if err != nil || len(jwkSet.Keys) != 1 {
		testingContext.Fatalf("retired key should remain published: keys=%d err=%v", len(jwkSet.Keys), err)
	}

	auditContext.RequestID = "request-4"
	if _, err := service.UpdateKeyStatus(ctx, auditContext, "payment-service", key.KeyID, KeyStatusArchived, "retention completed"); err != nil {
		testingContext.Fatalf("archive key: %v", err)
	}
	jwkSet, err = service.GetJWKSet(ctx, "payment-service")
	if err != nil || len(jwkSet.Keys) != 0 {
		testingContext.Fatalf("archived key should not be published: keys=%d err=%v", len(jwkSet.Keys), err)
	}
}

// TestServiceRejectsInvalidTransitions verifies invalid and unsafe transitions are rejected.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestServiceRejectsInvalidTransitions(testingContext *testing.T) {
	testingContext.Parallel()
	service := NewService(newMemoryStore(), nil)
	ctx := context.Background()
	auditContext := AuditContext{RequestID: "request-1", Actor: "security-operator"}
	_, _ = service.CreateIssuer(ctx, auditContext, "payment-service", "Payment Service", "")
	auditContext.RequestID = "request-2"
	key, err := service.ImportKey(ctx, auditContext, "payment-service", testJWK(testingContext, "key-1", "RS256"), "")
	if err != nil {
		testingContext.Fatalf("import key: %v", err)
	}

	auditContext.RequestID = "request-3"
	_, err = service.UpdateKeyStatus(ctx, auditContext, "payment-service", key.KeyID, KeyStatusRetired, "")
	assertDomainCode(testingContext, err, APIErrorInvalidKeyTransition)
	auditContext.RequestID = "request-4"
	_, err = service.UpdateKeyStatus(ctx, auditContext, "payment-service", key.KeyID, KeyStatusRevoked, "")
	assertDomainCode(testingContext, err, APIErrorValidation)
}

// TestServiceListsSuccessAndFailureAudits verifies actor metadata, status changes, filtering, and failure codes.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestServiceListsSuccessAndFailureAudits(testingContext *testing.T) {
	testingContext.Parallel()
	fixedTime := time.Date(2026, 11, 25, 11, 0, 0, 0, time.UTC)
	service := NewService(newMemoryStore(), func() time.Time { return fixedTime })
	ctx := context.Background()
	auditContext := AuditContext{RequestID: "audit-1", Actor: "security-operator", ClientIP: "127.0.0.1", UserAgent: "keypilot-test"}
	if _, err := service.CreateIssuer(ctx, auditContext, "payment-service", "Payment Service", ""); err != nil {
		testingContext.Fatalf("create issuer: %v", err)
	}
	if err := service.RecordFailure(ctx, AuditContext{RequestID: "audit-2", Actor: "anonymous", ClientIP: "127.0.0.2"}, AuditActionAuthentication, "", "", APIErrorUnauthorized, "administration token is invalid"); err != nil {
		testingContext.Fatalf("record failure audit: %v", err)
	}
	audits, err := service.ListAudits(ctx, "payment-service", 10)
	if err != nil || len(audits) != 1 {
		testingContext.Fatalf("list issuer audits: count=%d err=%v", len(audits), err)
	}
	if audits[0].Actor != "security-operator" || audits[0].ClientIP != "127.0.0.1" || audits[0].Result != AuditResultSuccess {
		testingContext.Fatalf("unexpected success audit: %+v", audits[0])
	}
	allAudits, err := service.ListAudits(ctx, "", 10)
	if err != nil || len(allAudits) != 2 || allAudits[1].ErrorCode != APIErrorUnauthorized {
		testingContext.Fatalf("unexpected audit list: audits=%+v err=%v", allAudits, err)
	}
	_, err = service.ListAudits(ctx, "", 0)
	assertDomainCode(testingContext, err, APIErrorValidation)
	canceledContext, cancel := context.WithCancel(context.Background())
	cancel()
	assertDomainCode(testingContext, service.CheckReady(canceledContext), APIErrorStorageUnavailable)
}

// testJWK creates a valid 2048-bit RSA public JWK for unit tests.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//   - keyID: JWK key identifier.
//   - algorithm: standard JWK algorithm value.
//
// Returns:
//   - RSAPublicJWK: generated public JWK.
func testJWK(testingContext *testing.T, keyID string, algorithm string) RSAPublicJWK {
	testingContext.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		testingContext.Fatalf("generate RSA key: %v", err)
	}
	exponent := big.NewInt(int64(privateKey.PublicKey.E)).Bytes()
	return RSAPublicJWK{
		KeyType: "RSA", KeyID: keyID, Use: "sig", Alg: algorithm,
		Modulus:  base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		Exponent: base64.RawURLEncoding.EncodeToString(exponent),
	}
}

// assertDomainCode verifies the stable API error code returned by a service operation.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//   - err: returned error.
//   - expectedCode: expected numeric API error code.
//
// Returns: None.
func assertDomainCode(testingContext *testing.T, err error, expectedCode APIErrorCode) {
	testingContext.Helper()
	var domainError *DomainError
	if !errors.As(err, &domainError) || domainError.Code != expectedCode {
		testingContext.Fatalf("expected domain code %d, got %v", expectedCode, err)
	}
}
