/*
Description: Tests KeyPilot operator backup and restore command behavior.
Author: vectorshi
Created: 2026-11-25
*/
package main

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	keypilotsqlite "github.com/agivector/keypilot/server/internal/storage/sqlite"
)

// TestRunBackupAndRestore verifies command parsing and successful SQLite operations.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestRunBackupAndRestore(testingContext *testing.T) {
	testingContext.Parallel()
	directory := testingContext.TempDir()
	sourcePath := filepath.Join(directory, "source.db")
	backupPath := filepath.Join(directory, "backup.db")
	restoredPath := filepath.Join(directory, "restored.db")
	store, err := keypilotsqlite.New(sourcePath)
	if err != nil {
		testingContext.Fatalf("create source database: %v", err)
	}
	if err := store.Close(); err != nil {
		testingContext.Fatalf("close source database: %v", err)
	}
	var output bytes.Buffer
	if err := run(context.Background(), []string{"backup", "--data-file", sourcePath, "--output", backupPath}, &output); err != nil {
		testingContext.Fatalf("run backup: %v", err)
	}
	if !strings.Contains(output.String(), "backup created") {
		testingContext.Fatalf("unexpected backup output: %q", output.String())
	}
	output.Reset()
	if err := run(context.Background(), []string{"restore", "--input", backupPath, "--data-file", restoredPath}, &output); err != nil {
		testingContext.Fatalf("run restore: %v", err)
	}
	if err := keypilotsqlite.IntegrityCheck(context.Background(), restoredPath); err != nil {
		testingContext.Fatalf("validate restored database: %v", err)
	}
}

// TestRunRejectsIncompleteCommands verifies required operator flags.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - testingContext: Go test context.
//
// Returns: None.
func TestRunRejectsIncompleteCommands(testingContext *testing.T) {
	testingContext.Parallel()
	if err := run(context.Background(), nil, &bytes.Buffer{}); err == nil {
		testingContext.Fatal("expected missing command rejection")
	}
	if err := run(context.Background(), []string{"backup"}, &bytes.Buffer{}); err == nil {
		testingContext.Fatal("expected missing backup output rejection")
	}
	if err := run(context.Background(), []string{"restore"}, &bytes.Buffer{}); err == nil {
		testingContext.Fatal("expected missing restore input rejection")
	}
}
