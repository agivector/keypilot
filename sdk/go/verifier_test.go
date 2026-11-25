/*
Description: Tests shared vectors and cache policy behavior of the KeyPilot Go SDK.
Author: vectorshi
Created: 2026-11-25
*/
package keypilot

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// vectorFile describes the shared cross-language signature cases.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type vectorFile struct {
	Version int          `json:"version"`
	Cases   []vectorCase `json:"cases"`
}

// vectorCase describes one shared verification expectation.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type vectorCase struct {
	Name              string          `json:"name"`
	PayloadBase64     string          `json:"payload_base64"`
	SignatureBase64   string          `json:"signature_base64url"`
	KeyID             string          `json:"kid"`
	Algorithm         CryptoAlgorithm `json:"algorithm"`
	ExpectedValid     bool            `json:"expected_valid"`
	ExpectedErrorCode *SDKErrorCode   `json:"expected_error_code"`
}

// mutableJWKSServer provides synchronized JWKS response changes for tests.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type mutableJWKSServer struct {
	mutex           sync.Mutex
	body            []byte
	etag            string
	status          int
	requests        int
	lastIfNoneMatch string
}

// ServeHTTP returns the current synchronized JWKS test response.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: incoming JWKS request.
//
// Returns: None.
func (server *mutableJWKSServer) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	server.mutex.Lock()
	defer server.mutex.Unlock()
	server.requests++
	server.lastIfNoneMatch = request.Header.Get("If-None-Match")
	if server.status != 0 && server.status != http.StatusOK {
		response.WriteHeader(server.status)
		return
	}
	if server.etag != "" && server.lastIfNoneMatch == server.etag {
		response.WriteHeader(http.StatusNotModified)
		return
	}
	response.Header().Set("Content-Type", "application/json")
	if server.etag != "" {
		response.Header().Set("ETag", server.etag)
	}
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(server.body)
}

// set replaces the synchronized JWKS response state.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - body: response JSON bytes.
//   - etag: response ETag.
//   - status: HTTP response status or zero for 200.
//
// Returns: None.
func (server *mutableJWKSServer) set(body []byte, etag string, status int) {
	server.mutex.Lock()
	defer server.mutex.Unlock()
	server.body = body
	server.etag = etag
	server.status = status
}

// snapshot returns request counters without a data race.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns:
//   - int: total request count.
//   - string: most recent If-None-Match value.
func (server *mutableJWKSServer) snapshot() (int, string) {
	server.mutex.Lock()
	defer server.mutex.Unlock()
	return server.requests, server.lastIfNoneMatch
}

// fakeClock provides synchronized deterministic time for cache tests.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type fakeClock struct {
	mutex sync.Mutex
	now   time.Time
}

// current returns the current fake time.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns:
//   - time.Time: deterministic current time.
func (clock *fakeClock) current() time.Time {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	return clock.now
}

// advance moves fake time forward by a duration.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - duration: positive duration to add.
//
// Returns: None.
func (clock *fakeClock) advance(duration time.Duration) {
	clock.mutex.Lock()
	defer clock.mutex.Unlock()
	clock.now = clock.now.Add(duration)
}

// TestSharedSignatureVectors verifies all fixed RS256 and PS256 cross-language cases.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestSharedSignatureVectors(testingContext *testing.T) {
	testingContext.Parallel()
	jwks := readVectorFile(testingContext, "keys", "rsa-public-jwks.json")
	casesContent := readVectorFile(testingContext, "cases", "signatures.json")
	var vectors vectorFile
	if err := json.Unmarshal(casesContent, &vectors); err != nil {
		testingContext.Fatalf("parse shared vectors: %v", err)
	}
	server := httptest.NewServer(&mutableJWKSServer{body: jwks, etag: `"vectors-v1"`})
	defer server.Close()
	verifier := newTestVerifier(testingContext, server.URL, FailureModeStrict)

	for _, testCase := range vectors.Cases {
		testCase := testCase
		testingContext.Run(testCase.Name, func(testingContext *testing.T) {
			payload, err := base64.RawURLEncoding.DecodeString(testCase.PayloadBase64)
			if err != nil {
				testingContext.Fatalf("decode payload: %v", err)
			}
			result, err := verifier.VerifyBase64URL(context.Background(), payload, testCase.SignatureBase64, testCase.KeyID, testCase.Algorithm)
			if testCase.ExpectedValid {
				if err != nil || !result.Valid || result.KeyID != testCase.KeyID || result.Algorithm != testCase.Algorithm {
					testingContext.Fatalf("expected valid result=%+v err=%v", result, err)
				}
				return
			}
			if err == nil || testCase.ExpectedErrorCode == nil || ErrorCode(err) != *testCase.ExpectedErrorCode {
				testingContext.Fatalf("expected error code=%v got=%v err=%v", testCase.ExpectedErrorCode, ErrorCode(err), err)
			}
		})
	}
}

// TestETagUnknownKeyCooldownAndReplacement verifies cache refresh lifecycle behavior.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestETagUnknownKeyCooldownAndReplacement(testingContext *testing.T) {
	testingContext.Parallel()
	jwks := readVectorFile(testingContext, "keys", "rsa-public-jwks.json")
	state := &mutableJWKSServer{body: jwks, etag: `"v1"`}
	server := httptest.NewServer(state)
	defer server.Close()
	verifier := newTestVerifier(testingContext, server.URL, FailureModeStrict)
	clock := &fakeClock{now: time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)}
	verifier.now = clock.current
	payload, signature := validRS256Input(testingContext)

	if _, err := verifier.Verify(context.Background(), payload, signature, "vector-rs256-2026-01", CryptoAlgorithmRS256); err != nil {
		testingContext.Fatalf("initial verify: %v", err)
	}
	clock.advance(2 * time.Minute)
	if _, err := verifier.Verify(context.Background(), payload, signature, "vector-rs256-2026-01", CryptoAlgorithmRS256); err != nil {
		testingContext.Fatalf("etag verify: %v", err)
	}
	requests, ifNoneMatch := state.snapshot()
	if requests != 2 || ifNoneMatch != `"v1"` {
		testingContext.Fatalf("expected ETag refresh requests=2 if-none-match=v1, got requests=%d header=%q", requests, ifNoneMatch)
	}

	if _, err := verifier.Verify(context.Background(), payload, signature, "unknown-1", CryptoAlgorithmRS256); ErrorCode(err) != SDKErrorKeyNotFound {
		testingContext.Fatalf("expected unknown key error, got %v", err)
	}
	requestsAfterFirstUnknown, _ := state.snapshot()
	if _, err := verifier.Verify(context.Background(), payload, signature, "unknown-2", CryptoAlgorithmRS256); ErrorCode(err) != SDKErrorKeyNotFound {
		testingContext.Fatalf("expected second unknown key error, got %v", err)
	}
	requestsAfterSecondUnknown, _ := state.snapshot()
	if requestsAfterFirstUnknown != 3 || requestsAfterSecondUnknown != 3 {
		testingContext.Fatalf("unknown kid cooldown failed first=%d second=%d", requestsAfterFirstUnknown, requestsAfterSecondUnknown)
	}

	psOnly := extractSingleJWK(testingContext, jwks, "vector-ps256-2026-01")
	state.set(psOnly, `"v2"`, http.StatusOK)
	clock.advance(2 * time.Minute)
	if _, err := verifier.ensureUsableCache(context.Background()); err != nil {
		testingContext.Fatalf("replace cache: %v", err)
	}
	if _, exists := verifier.cache.get("vector-rs256-2026-01"); exists {
		testingContext.Fatal("removed JWKS key remained in cache")
	}

	duplicate := duplicateJWKSet(testingContext, psOnly)
	state.set(duplicate, `"v3"`, http.StatusOK)
	if err := verifier.refresh(context.Background()); ErrorCode(err) != SDKErrorJWKSInvalidResponse {
		testingContext.Fatalf("expected duplicate kid rejection, got %v", err)
	}
	if _, exists := verifier.cache.get("vector-ps256-2026-01"); !exists {
		testingContext.Fatal("valid cache was lost after invalid refresh")
	}
}

// TestFailureModes verifies STRICT and AVAILABLE behavior around stale cached keys.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestFailureModes(testingContext *testing.T) {
	testingContext.Parallel()
	jwks := readVectorFile(testingContext, "keys", "rsa-public-jwks.json")
	payload, signature := validRS256Input(testingContext)

	testingContext.Run("strict", func(testingContext *testing.T) {
		state := &mutableJWKSServer{body: jwks, etag: `"strict-v1"`}
		server := httptest.NewServer(state)
		defer server.Close()
		verifier := newTestVerifier(testingContext, server.URL, FailureModeStrict)
		clock := &fakeClock{now: time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)}
		verifier.now = clock.current
		if _, err := verifier.Verify(context.Background(), payload, signature, "vector-rs256-2026-01", CryptoAlgorithmRS256); err != nil {
			testingContext.Fatalf("initial strict verify: %v", err)
		}
		state.set(nil, "", http.StatusServiceUnavailable)
		clock.advance(2 * time.Minute)
		if _, err := verifier.Verify(context.Background(), payload, signature, "vector-rs256-2026-01", CryptoAlgorithmRS256); ErrorCode(err) != SDKErrorCacheExpired {
			testingContext.Fatalf("expected strict cache expiration, got %v", err)
		}
	})

	testingContext.Run("available", func(testingContext *testing.T) {
		state := &mutableJWKSServer{body: jwks, etag: `"available-v1"`}
		server := httptest.NewServer(state)
		defer server.Close()
		verifier := newTestVerifier(testingContext, server.URL, FailureModeAvailable)
		clock := &fakeClock{now: time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)}
		verifier.now = clock.current
		if _, err := verifier.Verify(context.Background(), payload, signature, "vector-rs256-2026-01", CryptoAlgorithmRS256); err != nil {
			testingContext.Fatalf("initial available verify: %v", err)
		}
		state.set(nil, "", http.StatusServiceUnavailable)
		clock.advance(2 * time.Minute)
		if _, err := verifier.Verify(context.Background(), payload, signature, "vector-rs256-2026-01", CryptoAlgorithmRS256); err != nil {
			testingContext.Fatalf("available mode should use cache within max_stale: %v", err)
		}
		waitForRequests(testingContext, state, 2)
		clock.advance(2 * time.Minute)
		if _, err := verifier.Verify(context.Background(), payload, signature, "vector-rs256-2026-01", CryptoAlgorithmRS256); ErrorCode(err) != SDKErrorCacheExpired {
			testingContext.Fatalf("expected available cache expiration, got %v", err)
		}
	})
}

// TestStrictRevocationSLARejectsRemovedCachedKey verifies removal at the 60-second refresh boundary.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestStrictRevocationSLARejectsRemovedCachedKey(testingContext *testing.T) {
	testingContext.Parallel()
	jwks := readVectorFile(testingContext, "keys", "rsa-public-jwks.json")
	state := &mutableJWKSServer{body: jwks, etag: `"revocation-v1"`}
	server := httptest.NewServer(state)
	defer server.Close()
	verifier := newTestVerifier(testingContext, server.URL, FailureModeStrict)
	clock := &fakeClock{now: time.Date(2026, 11, 25, 0, 0, 0, 0, time.UTC)}
	verifier.now = clock.current
	payload, signature := validRS256Input(testingContext)
	if _, err := verifier.Verify(context.Background(), payload, signature, "vector-rs256-2026-01", CryptoAlgorithmRS256); err != nil {
		testingContext.Fatalf("initial verify: %v", err)
	}
	state.set(extractSingleJWK(testingContext, jwks, "vector-ps256-2026-01"), `"revocation-v2"`, http.StatusOK)
	clock.advance(time.Minute)
	if _, err := verifier.Verify(context.Background(), payload, signature, "vector-rs256-2026-01", CryptoAlgorithmRS256); ErrorCode(err) != SDKErrorKeyNotFound {
		testingContext.Fatalf("expected removed key rejection at refresh boundary, got %v", err)
	}
}

// TestConfigurationValidation verifies HTTPS enforcement and numeric enum validation.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestConfigurationValidation(testingContext *testing.T) {
	testingContext.Parallel()
	_, err := NewVerifier(Config{
		Issuer: "issuer", JWKSURL: "http://example.com/jwks.json",
		AllowedAlgorithms: []CryptoAlgorithm{CryptoAlgorithmRS256},
	})
	if ErrorCode(err) != SDKErrorConfiguration {
		testingContext.Fatalf("expected insecure URL rejection, got %v", err)
	}
	_, err = NewVerifier(Config{
		Issuer: "issuer", JWKSURL: "https://example.com/jwks.json",
		AllowedAlgorithms: []CryptoAlgorithm{CryptoAlgorithm(9999)},
	})
	if ErrorCode(err) != SDKErrorConfiguration {
		testingContext.Fatalf("expected invalid algorithm rejection, got %v", err)
	}
	normalized, err := normalizeConfig(Config{
		Issuer: "issuer", JWKSURL: "https://example.com/jwks.json",
		AllowedAlgorithms: []CryptoAlgorithm{CryptoAlgorithmRS256},
	})
	if err != nil || normalized.refreshInterval != time.Minute {
		testingContext.Fatalf("expected one-minute default refresh interval, config=%+v err=%v", normalized, err)
	}
}

// newTestVerifier creates a verifier with short deterministic cache policy values.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//   - jwksURL: local JWKS test URL.
//   - failureMode: cache failure policy.
//
// Returns:
//   - *Verifier: configured test verifier.
func newTestVerifier(testingContext *testing.T, jwksURL string, failureMode FailureMode) *Verifier {
	testingContext.Helper()
	verifier, err := NewVerifier(Config{
		Issuer: "vector-issuer", JWKSURL: jwksURL,
		AllowedAlgorithms: []CryptoAlgorithm{CryptoAlgorithmRS256, CryptoAlgorithmPS256},
		RefreshInterval:   time.Minute, RequestTimeout: time.Second,
		UnknownKIDCooldown: time.Minute, MaxStale: 3 * time.Minute, FailureMode: failureMode,
	})
	if err != nil {
		testingContext.Fatalf("create verifier: %v", err)
	}
	return verifier
}

// readVectorFile reads one shared vector file from the repository root.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//   - directory: vector subdirectory.
//   - name: vector file name.
//
// Returns:
//   - []byte: file content.
func readVectorFile(testingContext *testing.T, directory string, name string) []byte {
	testingContext.Helper()
	content, err := os.ReadFile(filepath.Join("..", "..", "test-vectors", directory, name))
	if err != nil {
		testingContext.Fatalf("read vector file: %v", err)
	}
	return content
}

// validRS256Input returns the payload and signature from the shared valid RS256 case.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns:
//   - []byte: decoded payload.
//   - []byte: decoded signature.
func validRS256Input(testingContext *testing.T) ([]byte, []byte) {
	testingContext.Helper()
	content := readVectorFile(testingContext, "cases", "signatures.json")
	var vectors vectorFile
	if err := json.Unmarshal(content, &vectors); err != nil {
		testingContext.Fatalf("parse vectors: %v", err)
	}
	for _, testCase := range vectors.Cases {
		if testCase.Name == "rs256_valid" {
			payload, payloadErr := base64.RawURLEncoding.DecodeString(testCase.PayloadBase64)
			signature, signatureErr := base64.RawURLEncoding.DecodeString(testCase.SignatureBase64)
			if payloadErr != nil || signatureErr != nil {
				testingContext.Fatalf("decode valid vector payload=%v signature=%v", payloadErr, signatureErr)
			}
			return payload, signature
		}
	}
	testingContext.Fatal("valid RS256 vector is missing")
	return nil, nil
}

// extractSingleJWK returns a JWKS document containing only the selected key.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//   - content: source JWKS bytes.
//   - keyID: key to retain.
//
// Returns:
//   - []byte: single-key JWKS JSON.
func extractSingleJWK(testingContext *testing.T, content []byte, keyID string) []byte {
	testingContext.Helper()
	var source map[string][]map[string]any
	if err := json.Unmarshal(content, &source); err != nil {
		testingContext.Fatalf("parse JWKS: %v", err)
	}
	for _, key := range source["keys"] {
		if key["kid"] == keyID {
			result, err := json.Marshal(map[string]any{"keys": []map[string]any{key}})
			if err != nil {
				testingContext.Fatalf("marshal single JWKS: %v", err)
			}
			return result
		}
	}
	testingContext.Fatalf("key %s not found", keyID)
	return nil
}

// duplicateJWKSet creates an invalid JWKS containing the same kid twice.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//   - content: valid single-key JWKS bytes.
//
// Returns:
//   - []byte: invalid duplicate-key JWKS JSON.
func duplicateJWKSet(testingContext *testing.T, content []byte) []byte {
	testingContext.Helper()
	var source map[string][]map[string]any
	if err := json.Unmarshal(content, &source); err != nil {
		testingContext.Fatalf("parse single JWKS: %v", err)
	}
	keys := source["keys"]
	result, err := json.Marshal(map[string]any{"keys": []map[string]any{keys[0], keys[0]}})
	if err != nil {
		testingContext.Fatalf("marshal duplicate JWKS: %v", err)
	}
	return result
}

// waitForRequests waits for an asynchronous refresh request to reach the test server.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//   - server: mutable JWKS test server.
//   - expected: minimum request count.
//
// Returns: None.
func waitForRequests(testingContext *testing.T, server *mutableJWKSServer, expected int) {
	testingContext.Helper()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		requests, _ := server.snapshot()
		if requests >= expected {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	requests, _ := server.snapshot()
	testingContext.Fatalf("expected at least %d requests, got %d", expected, requests)
}
