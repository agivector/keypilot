/*
Description: Provides atomic in-memory replacement for validated JWKS keys.
Author: vectorshi
Created: 2026-11-25
*/
package keypilot

import (
	"crypto/rsa"
	"sync"
	"time"
)

// cachedKey stores one validated RSA public key and its declared algorithm.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type cachedKey struct {
	publicKey *rsa.PublicKey
	algorithm CryptoAlgorithm
}

// keyCache stores the last complete valid JWKS snapshot.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type keyCache struct {
	mutex       sync.RWMutex
	keys        map[string]cachedKey
	etag        string
	refreshTime time.Time
}

// get returns one cached key by identifier.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - keyID: JWK key identifier.
//
// Returns:
//   - cachedKey: validated cached key.
//   - bool: true when the key exists.
func (cache *keyCache) get(keyID string) (cachedKey, bool) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	key, exists := cache.keys[keyID]
	return key, exists
}

// metadata returns the ETag, refresh time, and initialization state.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns:
//   - string: last accepted ETag.
//   - time.Time: last successful refresh time.
//   - bool: true after the first successful refresh.
func (cache *keyCache) metadata() (string, time.Time, bool) {
	cache.mutex.RLock()
	defer cache.mutex.RUnlock()
	return cache.etag, cache.refreshTime, !cache.refreshTime.IsZero()
}

// replace atomically installs a complete validated JWKS snapshot.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - keys: complete validated key set.
//   - etag: response ETag.
//   - refreshTime: successful refresh time.
//
// Returns: None.
func (cache *keyCache) replace(keys map[string]cachedKey, etag string, refreshTime time.Time) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.keys = keys
	cache.etag = etag
	cache.refreshTime = refreshTime
}

// touch records a successful 304 response without rebuilding the cache.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - refreshTime: successful refresh time.
//
// Returns: None.
func (cache *keyCache) touch(refreshTime time.Time) {
	cache.mutex.Lock()
	defer cache.mutex.Unlock()
	cache.refreshTime = refreshTime
}
