/*
Description: Defines and validates configuration for the KeyPilot Go SDK.
Author: vectorshi
Created: 2026-11-25
*/
package keypilot

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	defaultRefreshInterval    = time.Minute
	defaultRequestTimeout     = 3 * time.Second
	defaultUnknownKIDCooldown = 30 * time.Second
	defaultMaxStale           = 15 * time.Minute
)

// Config describes a verifier bound to one trusted issuer and fixed JWKS URL.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type Config struct {
	Issuer             string
	JWKSURL            string
	AllowedAlgorithms  []CryptoAlgorithm
	RefreshInterval    time.Duration
	RequestTimeout     time.Duration
	UnknownKIDCooldown time.Duration
	MaxStale           time.Duration
	FailureMode        FailureMode
	HTTPClient         *http.Client
}

// normalizedConfig stores validated configuration and an algorithm lookup set.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type normalizedConfig struct {
	issuer             string
	jwksURL            string
	allowedAlgorithms  map[CryptoAlgorithm]struct{}
	refreshInterval    time.Duration
	requestTimeout     time.Duration
	unknownKIDCooldown time.Duration
	maxStale           time.Duration
	failureMode        FailureMode
	httpClient         *http.Client
}

// normalizeConfig applies defaults and rejects unsafe or inconsistent values.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - config: caller-provided verifier configuration.
//
// Returns:
//   - normalizedConfig: validated internal configuration.
//   - error: CONFIGURATION_ERROR when validation fails.
func normalizeConfig(config Config) (normalizedConfig, error) {
	config.Issuer = strings.TrimSpace(config.Issuer)
	config.JWKSURL = strings.TrimSpace(config.JWKSURL)
	if config.Issuer == "" || config.JWKSURL == "" {
		return normalizedConfig{}, newSDKError(SDKErrorConfiguration, "issuer and jwks_url are required", nil)
	}
	if err := validateJWKSURL(config.JWKSURL); err != nil {
		return normalizedConfig{}, err
	}
	if len(config.AllowedAlgorithms) == 0 {
		return normalizedConfig{}, newSDKError(SDKErrorConfiguration, "allowed_algorithms is required", nil)
	}
	allowedAlgorithms := make(map[CryptoAlgorithm]struct{}, len(config.AllowedAlgorithms))
	for _, algorithm := range config.AllowedAlgorithms {
		if !algorithm.IsSupported() {
			return normalizedConfig{}, newSDKError(SDKErrorConfiguration, "allowed_algorithms contains an unsupported value", nil)
		}
		allowedAlgorithms[algorithm] = struct{}{}
	}
	if config.RefreshInterval == 0 {
		config.RefreshInterval = defaultRefreshInterval
	}
	if config.RequestTimeout == 0 {
		config.RequestTimeout = defaultRequestTimeout
	}
	if config.UnknownKIDCooldown == 0 {
		config.UnknownKIDCooldown = defaultUnknownKIDCooldown
	}
	if config.MaxStale == 0 {
		config.MaxStale = defaultMaxStale
	}
	if config.FailureMode == 0 {
		config.FailureMode = FailureModeStrict
	}
	if config.RefreshInterval <= 0 || config.RequestTimeout <= 0 || config.UnknownKIDCooldown <= 0 || config.MaxStale <= 0 {
		return normalizedConfig{}, newSDKError(SDKErrorConfiguration, "duration values must be positive", nil)
	}
	if config.MaxStale < config.RefreshInterval {
		return normalizedConfig{}, newSDKError(SDKErrorConfiguration, "max_stale must not be less than refresh_interval", nil)
	}
	if !config.FailureMode.IsValid() {
		return normalizedConfig{}, newSDKError(SDKErrorConfiguration, "failure_mode is invalid", nil)
	}
	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: config.RequestTimeout}
	}
	return normalizedConfig{
		issuer: config.Issuer, jwksURL: config.JWKSURL, allowedAlgorithms: allowedAlgorithms,
		refreshInterval: config.RefreshInterval, requestTimeout: config.RequestTimeout,
		unknownKIDCooldown: config.UnknownKIDCooldown, maxStale: config.MaxStale,
		failureMode: config.FailureMode, httpClient: httpClient,
	}, nil
}

// validateJWKSURL enforces HTTPS except for loopback hosts used by local tests.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - rawURL: configured JWKS URL.
//
// Returns:
//   - error: CONFIGURATION_ERROR when the URL is unsafe or invalid.
func validateJWKSURL(rawURL string) error {
	parsedURL, err := url.Parse(rawURL)
	if err != nil || parsedURL.Hostname() == "" {
		return newSDKError(SDKErrorConfiguration, "jwks_url is invalid", err)
	}
	if parsedURL.Scheme == "https" {
		return nil
	}
	if parsedURL.Scheme == "http" && isLoopbackHost(parsedURL.Hostname()) {
		return nil
	}
	return newSDKError(SDKErrorConfiguration, "jwks_url must use HTTPS except for localhost tests", nil)
}

// isLoopbackHost reports whether a hostname is safe for local HTTP tests.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - hostname: URL hostname without port.
//
// Returns:
//   - bool: true for localhost or loopback IP addresses.
func isLoopbackHost(hostname string) bool {
	if strings.EqualFold(hostname, "localhost") {
		return true
	}
	ipAddress := net.ParseIP(hostname)
	return ipAddress != nil && ipAddress.IsLoopback()
}
