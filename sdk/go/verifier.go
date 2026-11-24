/*
Description: Provides cached RS256 and PS256 signature verification for one trusted issuer.
Author: vectorshi
Created: 2026-11-25
*/
package keypilot

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"sync"
	"time"
)

// VerificationResult describes a successful local signature verification.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type VerificationResult struct {
	Valid     bool
	Issuer    string
	KeyID     string
	Algorithm CryptoAlgorithm
}

// Verifier manages one issuer-scoped JWKS cache and performs local verification.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type Verifier struct {
	config normalizedConfig
	cache  keyCache
	now    func() time.Time

	refreshMutex sync.Mutex
	refreshDone  chan struct{}
	refreshError error

	unknownMutex       sync.Mutex
	lastUnknownRefresh time.Time
}

// NewVerifier validates configuration and creates an empty issuer-scoped verifier.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - config: trusted issuer, fixed JWKS URL, algorithms, and cache policy.
//
// Returns:
//   - *Verifier: initialized verifier with lazy first refresh.
//   - error: CONFIGURATION_ERROR when configuration is invalid.
func NewVerifier(config Config) (*Verifier, error) {
	normalized, err := normalizeConfig(config)
	if err != nil {
		return nil, err
	}
	return &Verifier{config: normalized, now: time.Now}, nil
}

// Verify validates raw payload bytes and a raw RSA signature.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: cancellation context for any required JWKS refresh.
//   - payload: exact original business payload bytes.
//   - signature: raw RSA signature bytes.
//   - keyID: trusted issuer key identifier.
//   - algorithm: declared numeric signature algorithm.
//
// Returns:
//   - VerificationResult: successful verification details with Valid=true.
//   - error: stable SDK error for invalid input, refresh, key, or signature failures.
func (verifier *Verifier) Verify(ctx context.Context, payload []byte, signature []byte, keyID string, algorithm CryptoAlgorithm) (VerificationResult, error) {
	if verifier == nil || ctx == nil || len(payload) == 0 || len(signature) == 0 || strings.TrimSpace(keyID) == "" {
		return VerificationResult{}, newSDKError(SDKErrorInvalidArgument, "context, payload, signature, and kid are required", nil)
	}
	if !algorithm.IsSupported() {
		return VerificationResult{}, newSDKError(SDKErrorAlgorithmNotAllowed, "algorithm is not supported", nil)
	}
	if _, allowed := verifier.config.allowedAlgorithms[algorithm]; !allowed {
		return VerificationResult{}, newSDKError(SDKErrorAlgorithmNotAllowed, "algorithm is not allowed", nil)
	}
	refreshed, err := verifier.ensureUsableCache(ctx)
	if err != nil {
		return VerificationResult{}, err
	}
	key, exists := verifier.cache.get(keyID)
	if !exists && !refreshed {
		if err := verifier.refreshForUnknownKey(ctx); err != nil {
			return VerificationResult{}, err
		}
		key, exists = verifier.cache.get(keyID)
	}
	if !exists {
		return VerificationResult{}, newSDKError(SDKErrorKeyNotFound, "kid was not found in the trusted JWKS", nil)
	}
	if key.algorithm != algorithm {
		return VerificationResult{}, newSDKError(SDKErrorKeyInvalid, "JWK algorithm does not match requested algorithm", nil)
	}
	if err := verifyRSA(payload, signature, key.publicKey, algorithm); err != nil {
		return VerificationResult{}, err
	}
	return VerificationResult{Valid: true, Issuer: verifier.config.issuer, KeyID: keyID, Algorithm: algorithm}, nil
}

// VerifyBase64URL validates a payload with an unpadded Base64URL signature.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: cancellation context for any required JWKS refresh.
//   - payload: exact original business payload bytes.
//   - signature: unpadded Base64URL RSA signature.
//   - keyID: trusted issuer key identifier.
//   - algorithm: declared numeric signature algorithm.
//
// Returns:
//   - VerificationResult: successful verification details with Valid=true.
//   - error: INVALID_ARGUMENT for bad encoding or another stable SDK error.
func (verifier *Verifier) VerifyBase64URL(ctx context.Context, payload []byte, signature string, keyID string, algorithm CryptoAlgorithm) (VerificationResult, error) {
	signatureBytes, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return VerificationResult{}, newSDKError(SDKErrorInvalidArgument, "signature is not valid unpadded Base64URL", err)
	}
	return verifier.Verify(ctx, payload, signatureBytes, keyID, algorithm)
}

// ensureUsableCache applies STRICT or AVAILABLE refresh policy before key lookup.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: cancellation context for synchronous refresh.
//
// Returns:
//   - bool: true when this call completed a synchronous refresh.
//   - error: refresh error for first load or CACHE_EXPIRED for stale-cache failure.
func (verifier *Verifier) ensureUsableCache(ctx context.Context) (bool, error) {
	_, lastRefresh, initialized := verifier.cache.metadata()
	if !initialized {
		return true, verifier.refresh(ctx)
	}
	age := verifier.now().UTC().Sub(lastRefresh)
	if age < verifier.config.refreshInterval {
		return false, nil
	}
	if verifier.config.failureMode == FailureModeStrict || age > verifier.config.maxStale {
		if err := verifier.refresh(ctx); err != nil {
			return true, newSDKError(SDKErrorCacheExpired, "cached JWKS is outside the allowed refresh window", err)
		}
		return true, nil
	}
	verifier.refreshAsync()
	return false, nil
}

// refreshAsync starts a coalesced background refresh for AVAILABLE mode.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
func (verifier *Verifier) refreshAsync() {
	go func() {
		_ = verifier.refresh(context.Background())
	}()
}

// refreshForUnknownKey performs at most one immediate refresh per cooldown window.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: cancellation context for the refresh.
//
// Returns:
//   - error: refresh error, or nil when cooldown suppresses a request.
func (verifier *Verifier) refreshForUnknownKey(ctx context.Context) error {
	now := verifier.now().UTC()
	verifier.unknownMutex.Lock()
	if !verifier.lastUnknownRefresh.IsZero() && now.Sub(verifier.lastUnknownRefresh) < verifier.config.unknownKIDCooldown {
		verifier.unknownMutex.Unlock()
		return nil
	}
	verifier.lastUnknownRefresh = now
	verifier.unknownMutex.Unlock()
	return verifier.refresh(ctx)
}

// refresh coalesces concurrent requests and atomically applies a valid JWKS snapshot.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: cancellation context while waiting or fetching JWKS.
//
// Returns:
//   - error: JWKS_UNAVAILABLE or JWKS_INVALID_RESPONSE.
func (verifier *Verifier) refresh(ctx context.Context) error {
	verifier.refreshMutex.Lock()
	if verifier.refreshDone != nil {
		done := verifier.refreshDone
		verifier.refreshMutex.Unlock()
		select {
		case <-ctx.Done():
			return newSDKError(SDKErrorJWKSUnavailable, "waiting for JWKS refresh was canceled", ctx.Err())
		case <-done:
			verifier.refreshMutex.Lock()
			err := verifier.refreshError
			verifier.refreshMutex.Unlock()
			return err
		}
	}
	done := make(chan struct{})
	verifier.refreshDone = done
	verifier.refreshMutex.Unlock()

	etag, _, initialized := verifier.cache.metadata()
	keys, responseETag, notModified, err := fetchJWKS(ctx, verifier.config, etag)
	if err == nil {
		if notModified {
			if !initialized {
				err = newSDKError(SDKErrorJWKSInvalidResponse, "received 304 before a valid JWKS was cached", nil)
			} else {
				verifier.cache.touch(refreshTime(verifier.now))
			}
		} else {
			verifier.cache.replace(keys, responseETag, refreshTime(verifier.now))
		}
	}

	verifier.refreshMutex.Lock()
	verifier.refreshError = err
	verifier.refreshDone = nil
	close(done)
	verifier.refreshMutex.Unlock()
	return err
}

// verifyRSA performs RS256 or PS256 verification over the exact payload bytes.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - payload: exact original business payload bytes.
//   - signature: raw RSA signature bytes.
//   - publicKey: validated RSA public key.
//   - algorithm: requested numeric signature algorithm.
//
// Returns:
//   - error: SIGNATURE_INVALID or ALGORITHM_NOT_ALLOWED.
func verifyRSA(payload []byte, signature []byte, publicKey *rsa.PublicKey, algorithm CryptoAlgorithm) error {
	digest := sha256.Sum256(payload)
	var err error
	switch algorithm {
	case CryptoAlgorithmRS256:
		err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest[:], signature)
	case CryptoAlgorithmPS256:
		err = rsa.VerifyPSS(publicKey, crypto.SHA256, digest[:], signature, &rsa.PSSOptions{SaltLength: sha256.Size, Hash: crypto.SHA256})
	default:
		return newSDKError(SDKErrorAlgorithmNotAllowed, "algorithm is not supported", nil)
	}
	if err != nil {
		return newSDKError(SDKErrorSignatureInvalid, "signature verification failed", err)
	}
	return nil
}
