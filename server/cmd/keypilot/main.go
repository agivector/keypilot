/*
Description: Starts the KeyPilot HTTP server and coordinates graceful shutdown.
Author: vectorshi
Created: 2026-11-25
*/
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/codepunk-gm/keypilot/server/internal/config"
	"github.com/codepunk-gm/keypilot/server/internal/httpapi"
	"github.com/codepunk-gm/keypilot/server/internal/keyregistry"
	"github.com/codepunk-gm/keypilot/server/internal/storage/jsonfile"
)

// main runs the KeyPilot process and exits with a non-zero status on startup failure.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("keypilot stopped", "error", err)
		os.Exit(1)
	}
}

// run loads configuration, starts the HTTP server, and performs graceful shutdown.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - logger: structured application logger.
//
// Returns:
//   - error: configuration, storage, startup, or shutdown error.
func run(logger *slog.Logger) error {
	configuration, err := config.Load()
	if err != nil {
		return err
	}
	store, err := jsonfile.New(configuration.DataFile)
	if err != nil {
		return err
	}
	service := keyregistry.NewService(store, nil)
	server := &http.Server{
		Addr:              configuration.Address,
		Handler:           httpapi.New(service, configuration.AdminID, configuration.AdminToken, configuration.JWKSMaxAge),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("keypilot started", "address", configuration.Address, "data_file", configuration.DataFile)
		serverErrors <- server.ListenAndServe()
	}()

	shutdownSignals := make(chan os.Signal, 1)
	signal.Notify(shutdownSignals, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(shutdownSignals)

	select {
	case signalValue := <-shutdownSignals:
		logger.Info("shutdown requested", "signal", signalValue.String())
	case serverError := <-serverErrors:
		if !errors.Is(serverError, http.ErrServerClosed) {
			return serverError
		}
		return nil
	}

	shutdownContext, cancel := context.WithTimeout(context.Background(), configuration.ShutdownTimeout)
	defer cancel()
	return server.Shutdown(shutdownContext)
}
