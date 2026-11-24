/*
Description: Tests KeyPilot HTTP authentication, lifecycle API, JWKS publication, and ETag behavior.
Author: vectorshi
Created: 2026-11-25
*/
package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/codepunk-gm/keypilot/server/internal/keyregistry"
	"github.com/codepunk-gm/keypilot/server/internal/storage/jsonfile"
)

const testAdminToken = "0123456789abcdef-test-token"

// TestHandlerLifecycleAndJWKS verifies the complete administration and JWKS flow.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestHandlerLifecycleAndJWKS(testingContext *testing.T) {
	testingContext.Parallel()
	handler := testHandler(testingContext)

	issuerResponse := performJSON(testingContext, handler, http.MethodPost, "/admin/v1/issuers", map[string]any{
		"issuer": "payment-service", "displayName": "Payment Service",
	}, true, nil)
	if issuerResponse.Code != http.StatusCreated {
		testingContext.Fatalf("create issuer status=%d body=%s", issuerResponse.Code, issuerResponse.Body.String())
	}

	jwk := httpTestJWK(testingContext, "payment-2026-01", "PS256")
	keyResponse := performJSON(testingContext, handler, http.MethodPost, "/admin/v1/issuers/payment-service/keys", map[string]any{
		"description": "rotation key", "jwk": jwk,
	}, true, nil)
	if keyResponse.Code != http.StatusCreated {
		testingContext.Fatalf("import key status=%d body=%s", keyResponse.Code, keyResponse.Body.String())
	}

	activateResponse := performJSON(testingContext, handler, http.MethodPatch, "/admin/v1/issuers/payment-service/keys/payment-2026-01/status", map[string]any{
		"status": 2,
	}, true, nil)
	if activateResponse.Code != http.StatusOK {
		testingContext.Fatalf("activate key status=%d body=%s", activateResponse.Code, activateResponse.Body.String())
	}

	jwksResponse := performJSON(testingContext, handler, http.MethodGet, "/v1/issuers/payment-service/.well-known/jwks.json", nil, false, nil)
	if jwksResponse.Code != http.StatusOK || jwksResponse.Header().Get("ETag") == "" {
		testingContext.Fatalf("jwks status=%d etag=%q body=%s", jwksResponse.Code, jwksResponse.Header().Get("ETag"), jwksResponse.Body.String())
	}
	var jwkSet keyregistry.JWKSet
	if err := json.Unmarshal(jwksResponse.Body.Bytes(), &jwkSet); err != nil || len(jwkSet.Keys) != 1 {
		testingContext.Fatalf("unexpected jwks: keys=%d err=%v", len(jwkSet.Keys), err)
	}

	notModified := performJSON(testingContext, handler, http.MethodGet, "/v1/issuers/payment-service/.well-known/jwks.json", nil, false, map[string]string{
		"If-None-Match": jwksResponse.Header().Get("ETag"),
	})
	if notModified.Code != http.StatusNotModified {
		testingContext.Fatalf("expected 304, got %d", notModified.Code)
	}
}

// TestHandlerRejectsUnauthorizedAndPrivateJWK verifies management authentication and private key rejection.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestHandlerRejectsUnauthorizedAndPrivateJWK(testingContext *testing.T) {
	testingContext.Parallel()
	handler := testHandler(testingContext)
	unauthorized := performJSON(testingContext, handler, http.MethodGet, "/admin/v1/issuers", nil, false, nil)
	if unauthorized.Code != http.StatusUnauthorized {
		testingContext.Fatalf("expected unauthorized, got %d", unauthorized.Code)
	}

	_ = performJSON(testingContext, handler, http.MethodPost, "/admin/v1/issuers", map[string]any{
		"issuer": "payment-service", "displayName": "Payment Service",
	}, true, nil)
	jwk := httpTestJWK(testingContext, "key-1", "RS256")
	privateJWK := map[string]any{
		"kty": jwk.KeyType, "kid": jwk.KeyID, "use": jwk.Use, "alg": jwk.Alg,
		"n": jwk.Modulus, "e": jwk.Exponent, "d": "private-value",
	}
	response := performJSON(testingContext, handler, http.MethodPost, "/admin/v1/issuers/payment-service/keys", map[string]any{"jwk": privateJWK}, true, nil)
	if response.Code != http.StatusBadRequest || !bytes.Contains(response.Body.Bytes(), []byte(`"code":1003`)) {
		testingContext.Fatalf("expected private key rejection, status=%d body=%s", response.Code, response.Body.String())
	}
}

// testHandler creates a handler with isolated JSON persistence.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns:
//   - http.Handler: isolated KeyPilot handler.
func testHandler(testingContext *testing.T) http.Handler {
	testingContext.Helper()
	store, err := jsonfile.New(filepath.Join(testingContext.TempDir(), "keypilot.json"))
	if err != nil {
		testingContext.Fatalf("create store: %v", err)
	}
	return New(keyregistry.NewService(store, nil), testAdminToken, 300)
}

// performJSON executes one JSON HTTP request against a test handler.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//   - handler: HTTP handler under test.
//   - method: HTTP method.
//   - path: request path.
//   - body: optional JSON request body.
//   - authorized: whether to add the administration token.
//   - headers: optional additional headers.
//
// Returns:
//   - *httptest.ResponseRecorder: captured HTTP response.
func performJSON(testingContext *testing.T, handler http.Handler, method string, path string, body any, authorized bool, headers map[string]string) *httptest.ResponseRecorder {
	testingContext.Helper()
	var content []byte
	var err error
	if body != nil {
		content, err = json.Marshal(body)
		if err != nil {
			testingContext.Fatalf("marshal request body: %v", err)
		}
	}
	request := httptest.NewRequest(method, path, bytes.NewReader(content)).WithContext(context.Background())
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if authorized {
		request.Header.Set("Authorization", "Bearer "+testAdminToken)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

// httpTestJWK creates a valid RSA public JWK for HTTP tests.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//   - keyID: JWK key identifier.
//   - algorithm: standard JWK algorithm value.
//
// Returns:
//   - keyregistry.RSAPublicJWK: generated public JWK.
func httpTestJWK(testingContext *testing.T, keyID string, algorithm string) keyregistry.RSAPublicJWK {
	testingContext.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		testingContext.Fatalf("generate RSA key: %v", err)
	}
	return keyregistry.RSAPublicJWK{
		KeyType: "RSA", KeyID: keyID, Use: "sig", Alg: algorithm,
		Modulus:  base64.RawURLEncoding.EncodeToString(privateKey.PublicKey.N.Bytes()),
		Exponent: base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privateKey.PublicKey.E)).Bytes()),
	}
}
