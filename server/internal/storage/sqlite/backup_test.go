/*
Description: Tests consistent SQLite backup, integrity validation, and atomic restore behavior.
Author: vectorshi
Created: 2026-11-25
*/
package sqlite

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/codepunk-gm/keypilot/server/internal/keyregistry"
)

// TestBackupAndRestorePreserveSnapshot verifies online backup and stopped-service restore semantics.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestBackupAndRestorePreserveSnapshot(testingContext *testing.T) {
	testingContext.Parallel()
	directory := testingContext.TempDir()
	sourcePath := filepath.Join(directory, "source.db")
	backupPath := filepath.Join(directory, "backup.db")
	targetPath := filepath.Join(directory, "target.db")
	store, err := New(sourcePath)
	if err != nil {
		testingContext.Fatalf("create source store: %v", err)
	}
	now := time.Date(2026, 11, 25, 10, 0, 0, 0, time.UTC)
	firstIssuer := testIssuer(now, "first")
	if err := store.CreateIssuer(context.Background(), firstIssuer, testAudit(now, "1", keyregistry.AuditActionCreateIssuer)); err != nil {
		testingContext.Fatalf("create first issuer: %v", err)
	}
	if err := Backup(context.Background(), sourcePath, backupPath); err != nil {
		testingContext.Fatalf("backup database: %v", err)
	}
	if err := IntegrityCheck(context.Background(), backupPath); err != nil {
		testingContext.Fatalf("validate backup: %v", err)
	}
	secondIssuer := testIssuer(now, "second")
	if err := store.CreateIssuer(context.Background(), secondIssuer, testAudit(now, "2", keyregistry.AuditActionCreateIssuer)); err != nil {
		testingContext.Fatalf("create second issuer: %v", err)
	}
	if err := store.Close(); err != nil {
		testingContext.Fatalf("close source store: %v", err)
	}
	if err := Restore(context.Background(), backupPath, targetPath); err != nil {
		testingContext.Fatalf("restore backup: %v", err)
	}
	restored, err := New(targetPath)
	if err != nil {
		testingContext.Fatalf("open restored store: %v", err)
	}
	defer restored.Close()
	issuers, err := restored.ListIssuers(context.Background())
	if err != nil || len(issuers) != 1 || issuers[0].Issuer != firstIssuer.Issuer {
		testingContext.Fatalf("unexpected restored snapshot: issuers=%+v err=%v", issuers, err)
	}
}

// TestRestoreRejectsCorruptBackupWithoutReplacingTarget verifies pre-replacement integrity validation.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestRestoreRejectsCorruptBackupWithoutReplacingTarget(testingContext *testing.T) {
	testingContext.Parallel()
	directory := testingContext.TempDir()
	inputPath := filepath.Join(directory, "corrupt.db")
	targetPath := filepath.Join(directory, "target.db")
	if err := os.WriteFile(inputPath, []byte("not a SQLite database"), 0o600); err != nil {
		testingContext.Fatalf("write corrupt backup: %v", err)
	}
	original := []byte("existing target")
	if err := os.WriteFile(targetPath, original, 0o600); err != nil {
		testingContext.Fatalf("write target: %v", err)
	}
	if err := Restore(context.Background(), inputPath, targetPath); err == nil {
		testingContext.Fatal("expected corrupt backup rejection")
	}
	content, err := os.ReadFile(targetPath)
	if err != nil {
		testingContext.Fatalf("read target: %v", err)
	}
	if string(content) != string(original) {
		testingContext.Fatalf("target was replaced after failed validation: %q", content)
	}
}
