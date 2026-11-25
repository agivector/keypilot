/*
Description: Implements single-process atomic JSON file persistence for KeyPilot.
Author: vectorshi
Created: 2026-11-25
*/
package jsonfile

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"

	"github.com/agivector/keypilot/server/internal/keyregistry"
)

// Store persists KeyPilot state in one atomically replaced JSON file.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type Store struct {
	path  string
	mutex sync.RWMutex
	data  snapshot
}

// snapshot describes the complete file-backed persistence state.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type snapshot struct {
	Issuers map[string]keyregistry.Issuer                     `json:"issuers"`
	Keys    map[string]map[string]keyregistry.VerificationKey `json:"keys"`
	Audits  []keyregistry.AuditRecord                         `json:"audits"`
}

// New creates or loads a JSON file store.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - path: persistence file path.
//
// Returns:
//   - *Store: initialized JSON file store.
//   - error: directory, read, or decode error.
func New(path string) (*Store, error) {
	if path == "" {
		return nil, errors.New("data file path is required")
	}
	store := &Store{path: path, data: newSnapshot()}
	if err := store.load(); err != nil {
		return nil, err
	}
	return store, nil
}

// CreateIssuer atomically creates an issuer and its audit record.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: issuer to persist.
//   - audit: audit event to append.
//
// Returns:
//   - error: conflict, cancellation, or persistence error.
func (store *Store) CreateIssuer(ctx context.Context, issuer keyregistry.Issuer, audit keyregistry.AuditRecord) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, exists := store.data.Issuers[issuer.Issuer]; exists {
		return keyregistry.ErrStorageConflict
	}
	next := cloneSnapshot(store.data)
	next.Issuers[issuer.Issuer] = issuer
	next.Audits = append(next.Audits, audit)
	return store.commit(next)
}

// ListIssuers returns all persisted issuers.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//
// Returns:
//   - []keyregistry.Issuer: issuer list.
//   - error: cancellation error.
func (store *Store) ListIssuers(ctx context.Context) ([]keyregistry.Issuer, error) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	issuers := make([]keyregistry.Issuer, 0, len(store.data.Issuers))
	for _, issuer := range store.data.Issuers {
		issuers = append(issuers, issuer)
	}
	return issuers, nil
}

// GetIssuer returns one persisted issuer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: stable issuer identifier.
//
// Returns:
//   - keyregistry.Issuer: issuer record.
//   - error: not-found or cancellation error.
func (store *Store) GetIssuer(ctx context.Context, issuer string) (keyregistry.Issuer, error) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	if err := ctx.Err(); err != nil {
		return keyregistry.Issuer{}, err
	}
	record, exists := store.data.Issuers[issuer]
	if !exists {
		return keyregistry.Issuer{}, keyregistry.ErrStorageNotFound
	}
	return record, nil
}

// CreateKey atomically creates a verification key and its audit record.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - key: verification key to persist.
//   - audit: audit event to append.
//
// Returns:
//   - error: conflict, cancellation, or persistence error.
func (store *Store) CreateKey(ctx context.Context, key keyregistry.VerificationKey, audit keyregistry.AuditRecord) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, exists := store.data.Issuers[key.Issuer]; !exists {
		return keyregistry.ErrStorageNotFound
	}
	next := cloneSnapshot(store.data)
	issuerKeys := next.Keys[key.Issuer]
	if issuerKeys == nil {
		issuerKeys = make(map[string]keyregistry.VerificationKey)
		next.Keys[key.Issuer] = issuerKeys
	}
	if _, exists := issuerKeys[key.KeyID]; exists {
		return keyregistry.ErrStorageConflict
	}
	issuerKeys[key.KeyID] = key
	next.Audits = append(next.Audits, audit)
	return store.commit(next)
}

// ListKeys returns all verification keys for an issuer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: owner issuer identifier.
//
// Returns:
//   - []keyregistry.VerificationKey: verification key list.
//   - error: cancellation error.
func (store *Store) ListKeys(ctx context.Context, issuer string) ([]keyregistry.VerificationKey, error) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	issuerKeys := store.data.Keys[issuer]
	keys := make([]keyregistry.VerificationKey, 0, len(issuerKeys))
	for _, key := range issuerKeys {
		keys = append(keys, key)
	}
	return keys, nil
}

// GetKey returns one persisted verification key.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: owner issuer identifier.
//   - keyID: key identifier within the issuer.
//
// Returns:
//   - keyregistry.VerificationKey: verification key record.
//   - error: not-found or cancellation error.
func (store *Store) GetKey(ctx context.Context, issuer string, keyID string) (keyregistry.VerificationKey, error) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	if err := ctx.Err(); err != nil {
		return keyregistry.VerificationKey{}, err
	}
	key, exists := store.data.Keys[issuer][keyID]
	if !exists {
		return keyregistry.VerificationKey{}, keyregistry.ErrStorageNotFound
	}
	return key, nil
}

// UpdateKey atomically replaces a verification key and appends its audit record.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - key: updated verification key.
//   - audit: audit event to append.
//
// Returns:
//   - error: not-found, cancellation, or persistence error.
func (store *Store) UpdateKey(ctx context.Context, key keyregistry.VerificationKey, audit keyregistry.AuditRecord) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if _, exists := store.data.Keys[key.Issuer][key.KeyID]; !exists {
		return keyregistry.ErrStorageNotFound
	}
	next := cloneSnapshot(store.data)
	next.Keys[key.Issuer][key.KeyID] = key
	next.Audits = append(next.Audits, audit)
	return store.commit(next)
}

// AppendAudit atomically appends a standalone administration audit record.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - audit: audit record to persist.
//
// Returns:
//   - error: cancellation or persistence error.
func (store *Store) AppendAudit(ctx context.Context, audit keyregistry.AuditRecord) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	next := cloneSnapshot(store.data)
	next.Audits = append(next.Audits, audit)
	return store.commit(next)
}

// ListAudits returns a copy of all persisted administration audit records.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//
// Returns:
//   - []keyregistry.AuditRecord: audit records in persistence order.
//   - error: cancellation error.
func (store *Store) ListAudits(ctx context.Context) ([]keyregistry.AuditRecord, error) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]keyregistry.AuditRecord(nil), store.data.Audits...), nil
}

// load reads an existing snapshot from disk when the file exists.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - store: Store receiver.
//
// Returns:
//   - error: directory, file read, or JSON decode error.
func (store *Store) load() error {
	if err := os.MkdirAll(filepath.Dir(store.path), 0o750); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	content, err := os.ReadFile(store.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("read data file: %w", err)
	}
	if len(content) == 0 {
		return nil
	}
	loaded := newSnapshot()
	if err := json.Unmarshal(content, &loaded); err != nil {
		return fmt.Errorf("decode data file: %w", err)
	}
	normalizeSnapshot(&loaded)
	store.data = loaded
	return nil
}

// commit writes a complete snapshot to a temporary file and atomically replaces the data file.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - store: Store receiver.
//   - next: complete next snapshot.
//
// Returns:
//   - error: JSON encode, file sync, or rename error.
func (store *Store) commit(next snapshot) error {
	directory := filepath.Dir(store.path)
	temporaryFile, err := os.CreateTemp(directory, ".keypilot-*.tmp")
	if err != nil {
		return fmt.Errorf("create temporary data file: %w", err)
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)

	encoder := json.NewEncoder(temporaryFile)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(next); err != nil {
		temporaryFile.Close()
		return fmt.Errorf("encode data file: %w", err)
	}
	if err := temporaryFile.Sync(); err != nil {
		temporaryFile.Close()
		return fmt.Errorf("sync data file: %w", err)
	}
	if err := temporaryFile.Close(); err != nil {
		return fmt.Errorf("close data file: %w", err)
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return fmt.Errorf("set data file permissions: %w", err)
	}
	if err := os.Rename(temporaryPath, store.path); err != nil {
		return fmt.Errorf("replace data file: %w", err)
	}
	store.data = next
	return nil
}

// newSnapshot creates an initialized empty snapshot.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns:
//   - snapshot: initialized snapshot.
func newSnapshot() snapshot {
	return snapshot{
		Issuers: make(map[string]keyregistry.Issuer),
		Keys:    make(map[string]map[string]keyregistry.VerificationKey),
		Audits:  make([]keyregistry.AuditRecord, 0),
	}
}

// normalizeSnapshot initializes nil collections loaded from older or empty snapshots.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - data: snapshot to normalize.
//
// Returns: None.
func normalizeSnapshot(data *snapshot) {
	if data.Issuers == nil {
		data.Issuers = make(map[string]keyregistry.Issuer)
	}
	if data.Keys == nil {
		data.Keys = make(map[string]map[string]keyregistry.VerificationKey)
	}
	if data.Audits == nil {
		data.Audits = make([]keyregistry.AuditRecord, 0)
	}
}

// cloneSnapshot creates a deep copy suitable for atomic mutation.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - source: snapshot to clone.
//
// Returns:
//   - snapshot: deep copy of the source snapshot.
func cloneSnapshot(source snapshot) snapshot {
	result := newSnapshot()
	for identifier, issuer := range source.Issuers {
		result.Issuers[identifier] = issuer
	}
	issuerIdentifiers := make([]string, 0, len(source.Keys))
	for issuer := range source.Keys {
		issuerIdentifiers = append(issuerIdentifiers, issuer)
	}
	sort.Strings(issuerIdentifiers)
	for _, issuer := range issuerIdentifiers {
		result.Keys[issuer] = make(map[string]keyregistry.VerificationKey)
		for keyID, key := range source.Keys[issuer] {
			result.Keys[issuer][keyID] = key
		}
	}
	result.Audits = append(result.Audits, source.Audits...)
	return result
}
