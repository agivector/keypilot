/*
Description: Implements transactional SQLite persistence for KeyPilot.
Author: vectorshi
Created: 2026-11-25
*/
package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/agivector/keypilot/server/internal/keyregistry"
	_ "modernc.org/sqlite"
)

const schema = `
CREATE TABLE IF NOT EXISTS issuers (
    issuer TEXT PRIMARY KEY,
    payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS verification_keys (
    issuer TEXT NOT NULL,
    kid TEXT NOT NULL,
    payload BLOB NOT NULL,
    PRIMARY KEY (issuer, kid),
    FOREIGN KEY (issuer) REFERENCES issuers(issuer)
);
CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    payload BLOB NOT NULL
);`

// Store persists KeyPilot state in one transactional SQLite database.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type Store struct {
	database *sql.DB
}

// New opens a SQLite database and initializes the minimal KeyPilot schema.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - path: SQLite database file path.
//
// Returns:
//   - *Store: initialized SQLite store.
//   - error: directory, database, pragma, or schema initialization error.
func New(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("data file path is required")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}
	database, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open SQLite database: %w", err)
	}
	database.SetMaxOpenConns(1)
	database.SetMaxIdleConns(1)
	store := &Store{database: database}
	if err := store.initialize(context.Background()); err != nil {
		database.Close()
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		database.Close()
		return nil, fmt.Errorf("set SQLite database permissions: %w", err)
	}
	return store, nil
}

// Close releases the SQLite connection pool.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns:
//   - error: database close error.
func (store *Store) Close() error {
	return store.database.Close()
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
//   - error: conflict, cancellation, encoding, or transaction error.
func (store *Store) CreateIssuer(ctx context.Context, issuer keyregistry.Issuer, audit keyregistry.AuditRecord) error {
	issuerPayload, err := encodePayload(issuer)
	if err != nil {
		return err
	}
	return store.withTransaction(ctx, func(transaction *sql.Tx) error {
		if _, err := transaction.ExecContext(ctx, `INSERT INTO issuers (issuer, payload) VALUES (?, ?)`, issuer.Issuer, issuerPayload); err != nil {
			if isConstraintError(err) {
				return keyregistry.ErrStorageConflict
			}
			return err
		}
		return insertAudit(ctx, transaction, audit)
	})
}

// ListIssuers returns all persisted issuers in stable identifier order.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//
// Returns:
//   - []keyregistry.Issuer: issuer list.
//   - error: query, decode, or cancellation error.
func (store *Store) ListIssuers(ctx context.Context) ([]keyregistry.Issuer, error) {
	rows, err := store.database.QueryContext(ctx, `SELECT payload FROM issuers ORDER BY issuer`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	issuers := make([]keyregistry.Issuer, 0)
	for rows.Next() {
		issuer, err := scanPayload[keyregistry.Issuer](rows)
		if err != nil {
			return nil, err
		}
		issuers = append(issuers, issuer)
	}
	return issuers, rows.Err()
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
//   - error: not-found, query, decode, or cancellation error.
func (store *Store) GetIssuer(ctx context.Context, issuer string) (keyregistry.Issuer, error) {
	return queryPayload[keyregistry.Issuer](ctx, store.database, `SELECT payload FROM issuers WHERE issuer = ?`, issuer)
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
//   - error: not-found, conflict, cancellation, encoding, or transaction error.
func (store *Store) CreateKey(ctx context.Context, key keyregistry.VerificationKey, audit keyregistry.AuditRecord) error {
	keyPayload, err := encodePayload(key)
	if err != nil {
		return err
	}
	return store.withTransaction(ctx, func(transaction *sql.Tx) error {
		if err := ensureIssuerExists(ctx, transaction, key.Issuer); err != nil {
			return err
		}
		if _, err := transaction.ExecContext(ctx, `INSERT INTO verification_keys (issuer, kid, payload) VALUES (?, ?, ?)`, key.Issuer, key.KeyID, keyPayload); err != nil {
			if isConstraintError(err) {
				return keyregistry.ErrStorageConflict
			}
			return err
		}
		return insertAudit(ctx, transaction, audit)
	})
}

// ListKeys returns all verification keys for an issuer in stable key identifier order.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: owner issuer identifier.
//
// Returns:
//   - []keyregistry.VerificationKey: verification key list.
//   - error: query, decode, or cancellation error.
func (store *Store) ListKeys(ctx context.Context, issuer string) ([]keyregistry.VerificationKey, error) {
	rows, err := store.database.QueryContext(ctx, `SELECT payload FROM verification_keys WHERE issuer = ? ORDER BY kid`, issuer)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := make([]keyregistry.VerificationKey, 0)
	for rows.Next() {
		key, err := scanPayload[keyregistry.VerificationKey](rows)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

// GetKey returns one persisted verification key.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - issuer: owner issuer identifier.
//   - keyID: verification key identifier.
//
// Returns:
//   - keyregistry.VerificationKey: verification key record.
//   - error: not-found, query, decode, or cancellation error.
func (store *Store) GetKey(ctx context.Context, issuer string, keyID string) (keyregistry.VerificationKey, error) {
	return queryPayload[keyregistry.VerificationKey](ctx, store.database, `SELECT payload FROM verification_keys WHERE issuer = ? AND kid = ?`, issuer, keyID)
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
//   - error: not-found, cancellation, encoding, or transaction error.
func (store *Store) UpdateKey(ctx context.Context, key keyregistry.VerificationKey, audit keyregistry.AuditRecord) error {
	keyPayload, err := encodePayload(key)
	if err != nil {
		return err
	}
	return store.withTransaction(ctx, func(transaction *sql.Tx) error {
		result, err := transaction.ExecContext(ctx, `UPDATE verification_keys SET payload = ? WHERE issuer = ? AND kid = ?`, keyPayload, key.Issuer, key.KeyID)
		if err != nil {
			return err
		}
		updated, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if updated == 0 {
			return keyregistry.ErrStorageNotFound
		}
		return insertAudit(ctx, transaction, audit)
	})
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
//   - error: cancellation, encoding, or transaction error.
func (store *Store) AppendAudit(ctx context.Context, audit keyregistry.AuditRecord) error {
	return store.withTransaction(ctx, func(transaction *sql.Tx) error {
		return insertAudit(ctx, transaction, audit)
	})
}

// ListAudits returns persisted administration audits in insertion order.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//
// Returns:
//   - []keyregistry.AuditRecord: audit records in persistence order.
//   - error: query, decode, or cancellation error.
func (store *Store) ListAudits(ctx context.Context) ([]keyregistry.AuditRecord, error) {
	rows, err := store.database.QueryContext(ctx, `SELECT payload FROM audits ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	audits := make([]keyregistry.AuditRecord, 0)
	for rows.Next() {
		audit, err := scanPayload[keyregistry.AuditRecord](rows)
		if err != nil {
			return nil, err
		}
		audits = append(audits, audit)
	}
	return audits, rows.Err()
}

// initialize applies durable single-node pragmas and creates the schema.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: initialization context.
//
// Returns:
//   - error: pragma, connectivity, or schema error.
func (store *Store) initialize(ctx context.Context) error {
	statements := []string{
		`PRAGMA journal_mode = WAL`,
		`PRAGMA foreign_keys = ON`,
		`PRAGMA busy_timeout = 5000`,
		`PRAGMA synchronous = FULL`,
		schema,
	}
	for _, statement := range statements {
		if _, err := store.database.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("initialize SQLite database: %w", err)
		}
	}
	return store.database.PingContext(ctx)
}

// withTransaction executes one atomic SQLite mutation.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: transaction context.
//   - operation: mutation executed inside the transaction.
//
// Returns:
//   - error: operation, rollback, or commit error.
func (store *Store) withTransaction(ctx context.Context, operation func(*sql.Tx) error) error {
	transaction, err := store.database.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := operation(transaction); err != nil {
		if rollbackErr := transaction.Rollback(); rollbackErr != nil {
			return errors.Join(err, rollbackErr)
		}
		return err
	}
	return transaction.Commit()
}

// ensureIssuerExists verifies the parent issuer inside the current transaction.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - transaction: active SQLite transaction.
//   - issuer: issuer identifier to find.
//
// Returns:
//   - error: not-found, query, or cancellation error.
func ensureIssuerExists(ctx context.Context, transaction *sql.Tx, issuer string) error {
	var marker int
	if err := transaction.QueryRowContext(ctx, `SELECT 1 FROM issuers WHERE issuer = ?`, issuer).Scan(&marker); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return keyregistry.ErrStorageNotFound
		}
		return err
	}
	return nil
}

// insertAudit stores one audit payload using an active transaction.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - transaction: active SQLite transaction.
//   - audit: audit record to persist.
//
// Returns:
//   - error: encoding, insert, or cancellation error.
func insertAudit(ctx context.Context, transaction *sql.Tx, audit keyregistry.AuditRecord) error {
	payload, err := encodePayload(audit)
	if err != nil {
		return err
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO audits (payload) VALUES (?)`, payload)
	return err
}

// encodePayload serializes one domain record for storage.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - value: domain record to encode.
//
// Returns:
//   - []byte: UTF-8 JSON payload.
//   - error: JSON encoding error.
func encodePayload(value any) ([]byte, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode storage payload: %w", err)
	}
	return payload, nil
}

// queryPayload loads and decodes one domain record.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//   - database: SQLite query interface.
//   - query: parameterized single-row SQL query.
//   - arguments: query arguments.
//
// Returns:
//   - T: decoded domain record.
//   - error: not-found, query, decode, or cancellation error.
func queryPayload[T any](ctx context.Context, database *sql.DB, query string, arguments ...any) (T, error) {
	var result T
	var payload []byte
	if err := database.QueryRowContext(ctx, query, arguments...).Scan(&payload); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return result, keyregistry.ErrStorageNotFound
		}
		return result, err
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return result, fmt.Errorf("decode storage payload: %w", err)
	}
	return result, nil
}

// scanPayload decodes one payload from the current SQL row.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - scanner: current SQL row scanner.
//
// Returns:
//   - T: decoded domain record.
//   - error: scan or JSON decode error.
func scanPayload[T any](scanner interface{ Scan(...any) error }) (T, error) {
	var result T
	var payload []byte
	if err := scanner.Scan(&payload); err != nil {
		return result, err
	}
	if err := json.Unmarshal(payload, &result); err != nil {
		return result, fmt.Errorf("decode storage payload: %w", err)
	}
	return result, nil
}

// isConstraintError reports whether SQLite rejected a uniqueness or integrity constraint.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - err: SQLite execution error.
//
// Returns:
//   - bool: true for a SQLite constraint failure.
func isConstraintError(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "constraint failed")
}
