/*
Description: Provides operational SQLite backup and stopped-service restore commands.
Author: vectorshi
Created: 2026-11-25
*/
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	keypilotsqlite "github.com/codepunk-gm/keypilot/server/internal/storage/sqlite"
)

// main executes one KeyPilot operator command and returns a non-zero process status on failure.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
func main() {
	if err := run(context.Background(), os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// run parses and executes one supported operator command.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: command context.
//   - arguments: command-line arguments excluding the executable name.
//   - output: successful command output destination.
//
// Returns:
//   - error: usage, backup, or restore error.
func run(ctx context.Context, arguments []string, output io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("usage: keypilotctl <backup|restore> [options]")
	}
	switch arguments[0] {
	case "backup":
		return runBackup(ctx, arguments[1:], output)
	case "restore":
		return runRestore(ctx, arguments[1:], output)
	default:
		return fmt.Errorf("unsupported command %q; expected backup or restore", arguments[0])
	}
}

// runBackup creates one consistent SQLite backup.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: command context.
//   - arguments: backup flags.
//   - output: successful command output destination.
//
// Returns:
//   - error: flag parsing, validation, or backup error.
func runBackup(ctx context.Context, arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("backup", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	dataFile := flags.String("data-file", "data/keypilot.db", "source SQLite database path")
	backupFile := flags.String("output", "", "destination backup path")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse backup flags: %w", err)
	}
	if *backupFile == "" {
		return errors.New("backup --output is required")
	}
	if err := keypilotsqlite.Backup(ctx, *dataFile, *backupFile); err != nil {
		return err
	}
	fmt.Fprintf(output, "backup created: %s\n", *backupFile)
	return nil
}

// runRestore validates and atomically restores one SQLite backup while the service is stopped.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: command context.
//   - arguments: restore flags.
//   - output: successful command output destination.
//
// Returns:
//   - error: flag parsing, validation, or restore error.
func runRestore(ctx context.Context, arguments []string, output io.Writer) error {
	flags := flag.NewFlagSet("restore", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	backupFile := flags.String("input", "", "source backup path")
	dataFile := flags.String("data-file", "data/keypilot.db", "target SQLite database path")
	if err := flags.Parse(arguments); err != nil {
		return fmt.Errorf("parse restore flags: %w", err)
	}
	if *backupFile == "" {
		return errors.New("restore --input is required")
	}
	if err := keypilotsqlite.Restore(ctx, *backupFile, *dataFile); err != nil {
		return err
	}
	fmt.Fprintf(output, "restore completed: %s\n", *dataFile)
	return nil
}
