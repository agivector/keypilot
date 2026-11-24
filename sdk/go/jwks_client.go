/*
Description: Fetches, parses, and validates complete RSA JWKS responses.
Author: vectorshi
Created: 2026-11-25
*/
package keypilot

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"
)

const maxJWKSResponseBytes = 1024 * 1024

// rsaPublicJWK describes supported public and forbidden private RSA JWK fields.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type rsaPublicJWK struct {
	KeyType       string          `json:"kty"`
	KeyID         string          `json:"kid"`
	Use           string          `json:"use"`
	Algorithm     string          `json:"alg"`
	Modulus       string          `json:"n"`
	Exponent      string          `json:"e"`
	PrivateD      json.RawMessage `json:"d"`
	PrivateP      json.RawMessage `json:"p"`
	PrivateQ      json.RawMessage `json:"q"`
	PrivateDP     json.RawMessage `json:"dp"`
	PrivateDQ     json.RawMessage `json:"dq"`
	PrivateQI     json.RawMessage `json:"qi"`
	PrivatePrimes json.RawMessage `json:"oth"`
}

// jwkSet describes a standard JWKS response.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type jwkSet struct {
	Keys []rsaPublicJWK `json:"keys"`
}

// fetchJWKS retrieves and validates one complete JWKS snapshot.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request cancellation context.
//   - config: validated verifier configuration.
//   - etag: optional ETag from the current cache.
//
// Returns:
//   - map[string]cachedKey: complete validated key set when modified.
//   - string: response ETag.
//   - bool: true for a 304 Not Modified response.
//   - error: JWKS_UNAVAILABLE or JWKS_INVALID_RESPONSE.
func fetchJWKS(ctx context.Context, config normalizedConfig, etag string) (map[string]cachedKey, string, bool, error) {
	requestContext, cancel := context.WithTimeout(ctx, config.requestTimeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, config.jwksURL, nil)
	if err != nil {
		return nil, "", false, newSDKError(SDKErrorJWKSUnavailable, "create JWKS request failed", err)
	}
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	response, err := config.httpClient.Do(request)
	if err != nil {
		return nil, "", false, newSDKError(SDKErrorJWKSUnavailable, "request JWKS failed", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return nil, etag, true, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, "", false, newSDKError(SDKErrorJWKSUnavailable, fmt.Sprintf("JWKS endpoint returned status %d", response.StatusCode), nil)
	}
	limitedBody := io.LimitReader(response.Body, maxJWKSResponseBytes+1)
	body, err := io.ReadAll(limitedBody)
	if err != nil {
		return nil, "", false, newSDKError(SDKErrorJWKSUnavailable, "read JWKS response failed", err)
	}
	if len(body) > maxJWKSResponseBytes {
		return nil, "", false, newSDKError(SDKErrorJWKSInvalidResponse, "JWKS response exceeds size limit", nil)
	}
	keys, err := parseJWKS(body, config.allowedAlgorithms)
	if err != nil {
		return nil, "", false, err
	}
	return keys, response.Header.Get("ETag"), false, nil
}

// parseJWKS validates every JWK before returning an atomic replacement set.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - content: raw JWKS JSON bytes.
//   - allowedAlgorithms: configured algorithm whitelist.
//
// Returns:
//   - map[string]cachedKey: complete validated key set.
//   - error: JWKS_INVALID_RESPONSE when any key is invalid.
func parseJWKS(content []byte, allowedAlgorithms map[CryptoAlgorithm]struct{}) (map[string]cachedKey, error) {
	var set jwkSet
	if err := json.Unmarshal(content, &set); err != nil || set.Keys == nil {
		return nil, newSDKError(SDKErrorJWKSInvalidResponse, "JWKS JSON is invalid or keys is missing", err)
	}
	keys := make(map[string]cachedKey, len(set.Keys))
	for _, jwk := range set.Keys {
		key, err := parseJWK(jwk, allowedAlgorithms)
		if err != nil {
			return nil, err
		}
		if _, exists := keys[jwk.KeyID]; exists {
			return nil, newSDKError(SDKErrorJWKSInvalidResponse, "JWKS contains duplicate kid", nil)
		}
		keys[jwk.KeyID] = key
	}
	return keys, nil
}

// parseJWK validates one RSA public JWK and constructs its public key.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - jwk: RSA JWK value from the response.
//   - allowedAlgorithms: configured algorithm whitelist.
//
// Returns:
//   - cachedKey: validated RSA key and algorithm.
//   - error: JWKS_INVALID_RESPONSE when validation fails.
func parseJWK(jwk rsaPublicJWK, allowedAlgorithms map[CryptoAlgorithm]struct{}) (cachedKey, error) {
	if jwk.KeyType != "RSA" || jwk.Use != "sig" || strings.TrimSpace(jwk.KeyID) == "" || jwk.KeyID != strings.TrimSpace(jwk.KeyID) {
		return cachedKey{}, newSDKError(SDKErrorJWKSInvalidResponse, "JWK kty, use, or kid is invalid", nil)
	}
	if hasPrivateJWKField(jwk) {
		return cachedKey{}, newSDKError(SDKErrorJWKSInvalidResponse, "private RSA JWK fields are not allowed", nil)
	}
	algorithm, err := algorithmFromJWK(jwk.Algorithm)
	if err != nil {
		return cachedKey{}, err
	}
	if _, allowed := allowedAlgorithms[algorithm]; !allowed {
		return cachedKey{}, newSDKError(SDKErrorJWKSInvalidResponse, "JWK algorithm is not allowed by verifier configuration", nil)
	}
	modulusBytes, err := base64.RawURLEncoding.DecodeString(jwk.Modulus)
	if err != nil || len(modulusBytes) == 0 {
		return cachedKey{}, newSDKError(SDKErrorJWKSInvalidResponse, "JWK modulus is invalid", err)
	}
	exponentBytes, err := base64.RawURLEncoding.DecodeString(jwk.Exponent)
	if err != nil || len(exponentBytes) == 0 || len(exponentBytes) > 4 {
		return cachedKey{}, newSDKError(SDKErrorJWKSInvalidResponse, "JWK exponent is invalid", err)
	}
	exponentValue := new(big.Int).SetBytes(exponentBytes)
	if !exponentValue.IsInt64() {
		return cachedKey{}, newSDKError(SDKErrorJWKSInvalidResponse, "JWK exponent is too large", nil)
	}
	exponent := int(exponentValue.Int64())
	if exponent < 3 || exponent%2 == 0 {
		return cachedKey{}, newSDKError(SDKErrorJWKSInvalidResponse, "JWK exponent is invalid", nil)
	}
	publicKey := &rsa.PublicKey{N: new(big.Int).SetBytes(modulusBytes), E: exponent}
	if publicKey.N.BitLen() < 2048 {
		return cachedKey{}, newSDKError(SDKErrorJWKSInvalidResponse, "RSA key size must be at least 2048 bits", nil)
	}
	return cachedKey{publicKey: publicKey, algorithm: algorithm}, nil
}

// hasPrivateJWKField reports whether a JWK contains any RSA private parameter.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - jwk: parsed RSA JWK.
//
// Returns:
//   - bool: true when a private field is present.
func hasPrivateJWKField(jwk rsaPublicJWK) bool {
	return len(jwk.PrivateD) > 0 || len(jwk.PrivateP) > 0 || len(jwk.PrivateQ) > 0 ||
		len(jwk.PrivateDP) > 0 || len(jwk.PrivateDQ) > 0 || len(jwk.PrivateQI) > 0 || len(jwk.PrivatePrimes) > 0
}

// algorithmFromJWK maps a standard JWK algorithm string to a numeric enum.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - algorithm: standard JWK alg value.
//
// Returns:
//   - CryptoAlgorithm: mapped numeric algorithm.
//   - error: JWKS_INVALID_RESPONSE for unsupported values.
func algorithmFromJWK(algorithm string) (CryptoAlgorithm, error) {
	switch algorithm {
	case "RS256":
		return CryptoAlgorithmRS256, nil
	case "PS256":
		return CryptoAlgorithmPS256, nil
	default:
		return 0, newSDKError(SDKErrorJWKSInvalidResponse, "JWK algorithm is unsupported", nil)
	}
}

// refreshTime returns a UTC timestamp for successful cache refreshes.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - now: clock function used by the verifier.
//
// Returns:
//   - time.Time: current UTC time.
func refreshTime(now func() time.Time) time.Time {
	return now().UTC()
}
