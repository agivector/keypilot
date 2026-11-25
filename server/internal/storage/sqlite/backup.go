/*
Description: Provides consistent SQLite backup validation and atomic restore operations.
Author: vectorshi
Created: 2026-11-25
*/
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Backup creates a consistent SQLite snapshot and atomically publishes it at the output path.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: backup context.
//   - sourcePath: active SQLite database path.
//   - outputPath: destination snapshot path.
//
// Returns:
//   - error: validation, database, snapshot, sync, or replacement error.
func Backup(ctx context.Context, sourcePath string, outputPath string) error {
	if err := validateDistinctPaths(sourcePath, outputPath); err != nil {
		return err
	}
	if _, err := os.Stat(sourcePath); err != nil {
		return fmt.Errorf("read source database: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(outputPath), 0o750); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	temporaryPath, err := unusedTemporaryPath(filepath.Dir(outputPath), ".keypilot-backup-*.db")
	if err != nil {
		return err
	}
	defer os.Remove(temporaryPath)

	database, err := sql.Open("sqlite", sourcePath)
	if err != nil {
		return fmt.Errorf("open source database: %w", err)
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	if _, err := database.ExecContext(ctx, `PRAGMA busy_timeout = 5000`); err != nil {
		return fmt.Errorf("configure backup connection: %w", err)
	}
	statement := `VACUUM INTO '` + strings.ReplaceAll(temporaryPath, `'`, `''`) + `'`
	if _, err := database.ExecContext(ctx, statement); err != nil {
		return fmt.Errorf("create SQLite backup: %w", err)
	}
	if err := syncFile(temporaryPath); err != nil {
		return err
	}
	if err := os.Chmod(temporaryPath, 0o600); err != nil {
		return fmt.Errorf("set backup permissions: %w", err)
	}
	if err := os.Rename(temporaryPath, outputPath); err != nil {
		return fmt.Errorf("publish backup: %w", err)
	}
	return syncDirectory(filepath.Dir(outputPath))
}

// Restore validates a stopped-service backup and atomically replaces the target database.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: restore context.
//   - inputPath: validated SQLite backup path.
//   - targetPath: stopped KeyPilot database path to replace.
//
// Returns:
//   - error: integrity, copy, sync, or replacement error.
func Restore(ctx context.Context, inputPath string, targetPath string) error {
	if err := validateDistinctPaths(inputPath, targetPath); err != nil {
		return err
	}
	if err := IntegrityCheck(ctx, inputPath); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(targetPath), 0o750); err != nil {
		return fmt.Errorf("create restore directory: %w", err)
	}
	temporaryFile, err := os.CreateTemp(filepath.Dir(targetPath), ".keypilot-restore-*.db")
	if err != nil {
		return fmt.Errorf("create restore file: %w", err)
	}
	temporaryPath := temporaryFile.Name()
	defer os.Remove(temporaryPath)

	inputFile, err := os.Open(inputPath)
	if err != nil {
		temporaryFile.Close()
		return fmt.Errorf("open backup: %w", err)
	}
	_, copyErr := io.Copy(temporaryFile, inputFile)
	inputCloseErr := inputFile.Close()
	if copyErr != nil {
		temporaryFile.Close()
		return fmt.Errorf("copy backup: %w", copyErr)
	}
	if inputCloseErr != nil {
		temporaryFile.Close()
		return fmt.Errorf("close backup: %w", inputCloseErr)
	}
	if err := temporaryFile.Sync(); err != nil {
		temporaryFile.Close()
		return fmt.Errorf("sync restored database: %w", err)
	}
	if err := temporaryFile.Chmod(0o600); err != nil {
		temporaryFile.Close()
		return fmt.Errorf("set restored database permissions: %w", err)
	}
	if err := temporaryFile.Close(); err != nil {
		return fmt.Errorf("close restored database: %w", err)
	}
	if err := removeSQLiteSidecars(targetPath); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, targetPath); err != nil {
		return fmt.Errorf("replace target database: %w", err)
	}
	return syncDirectory(filepath.Dir(targetPath))
}

// IntegrityCheck verifies that SQLite reports a complete healthy database.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: validation context.
//   - path: SQLite database path to validate read-only.
//
// Returns:
//   - error: open, query, cancellation, or integrity error.
func IntegrityCheck(ctx context.Context, path string) error {
	if strings.TrimSpace(path) == "" {
		return errors.New("database path is required")
	}
	absolutePath, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve database path: %w", err)
	}
	databaseURL := (&url.URL{Scheme: "file", Path: absolutePath}).String() + "?mode=ro"
	database, err := sql.Open("sqlite", databaseURL)
	if err != nil {
		return fmt.Errorf("open database for integrity check: %w", err)
	}
	database.SetMaxOpenConns(1)
	defer database.Close()
	rows, err := database.QueryContext(ctx, `PRAGMA integrity_check`)
	if err != nil {
		return fmt.Errorf("run integrity check: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var result string
		if err := rows.Scan(&result); err != nil {
			return fmt.Errorf("read integrity result: %w", err)
		}
		if result != "ok" {
			return fmt.Errorf("SQLite integrity check failed: %s", result)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("read integrity results: %w", err)
	}
	return nil
}

// validateDistinctPaths rejects empty or identical source and destination paths.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - sourcePath: source database path.
//   - targetPath: destination database path.
//
// Returns:
//   - error: path validation error.
func validateDistinctPaths(sourcePath string, targetPath string) error {
	if strings.TrimSpace(sourcePath) == "" || strings.TrimSpace(targetPath) == "" {
		return errors.New("source and destination database paths are required")
	}
	sourceAbsolute, err := filepath.Abs(sourcePath)
	if err != nil {
		return fmt.Errorf("resolve source path: %w", err)
	}
	targetAbsolute, err := filepath.Abs(targetPath)
	if err != nil {
		return fmt.Errorf("resolve destination path: %w", err)
	}
	if sourceAbsolute == targetAbsolute {
		return errors.New("source and destination database paths must differ")
	}
	return nil
}

// unusedTemporaryPath reserves and releases a unique path required by VACUUM INTO.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - directory: directory that will contain the temporary file.
//   - pattern: temporary filename pattern.
//
// Returns:
//   - string: unique path that does not exist.
//   - error: temporary path allocation error.
func unusedTemporaryPath(directory string, pattern string) (string, error) {
	temporaryFile, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return "", fmt.Errorf("allocate temporary backup path: %w", err)
	}
	path := temporaryFile.Name()
	if err := temporaryFile.Close(); err != nil {
		return "", fmt.Errorf("close temporary path: %w", err)
	}
	if err := os.Remove(path); err != nil {
		return "", fmt.Errorf("release temporary path: %w", err)
	}
	return path, nil
}

// syncFile flushes one completed file to durable storage.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - path: file path to synchronize.
//
// Returns:
//   - error: open, sync, or close error.
func syncFile(path string) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return fmt.Errorf("open file for sync: %w", err)
	}
	if err := file.Sync(); err != nil {
		file.Close()
		return fmt.Errorf("sync file: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close synced file: %w", err)
	}
	return nil
}

// syncDirectory flushes a directory entry update after atomic replacement.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - path: directory path to synchronize.
//
// Returns:
//   - error: open, sync, or close error.
func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open directory for sync: %w", err)
	}
	if err := directory.Sync(); err != nil {
		directory.Close()
		return fmt.Errorf("sync directory: %w", err)
	}
	if err := directory.Close(); err != nil {
		return fmt.Errorf("close synced directory: %w", err)
	}
	return nil
}

// removeSQLiteSidecars removes stale WAL and shared-memory files before stopped-service restore.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - targetPath: target SQLite database path.
//
// Returns:
//   - error: sidecar removal error other than not-exist.
func removeSQLiteSidecars(targetPath string) error {
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(targetPath + suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove SQLite sidecar: %w", err)
		}
	}
	return nil
}
