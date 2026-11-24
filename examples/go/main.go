/*
Description: Demonstrates minimal Go SDK verification against a running KeyPilot JWKS endpoint.
Author: vectorshi
Created: 2026-11-25
*/
package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"os"
	"strconv"

	keypilot "github.com/codepunk-gm/keypilot/sdk/go"
)

const (
	defaultPayload   = "b3JkZXJfaWQ9S1AtMjAyNi0wMDAxJmFtb3VudD0xOTk5JmN1cnJlbmN5PUNOWQ"
	defaultSignature = "o_ZG9_pHw8Mx-EKyO-dkph6KFX0Z8xmPo_LbWyk1hCPsiaRIboCnqjv7ZiMTrbAqHVPddJLd_ILND30viCKLm5ixFUwVUGRwV1nEyQ4DdycNZoq0zem_vDC1KIwGU_6phN4VDbZ2mu1q1a20BOx7piIu8XxLj3mwXpnga8O8eVKcwYhP5KNx7oINWBeNjg2wmOryxWl55lIRS8xs7XBPlSH-13yb4zWmjRfYMfn10iMY2bFqDGNM8Qc8y0W8xOyg5iodh3R6_5RhIWE-Bl-cw1LBUO2Y3twQl6UVWpmbMNDsVxq6ZnBzHOOU9Qoo8h4PhxwTcHL9oamnEPDbn12ezw"
)

// main loads example inputs from environment variables and verifies one signature.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
func main() {
	issuer := environment("KEYPILOT_EXAMPLE_ISSUER", "vector-issuer")
	jwksURL := environment("KEYPILOT_EXAMPLE_JWKS_URL", "http://127.0.0.1:8080/v1/issuers/vector-issuer/.well-known/jwks.json")
	keyID := environment("KEYPILOT_EXAMPLE_KID", "vector-rs256-2026-01")
	algorithm := parseAlgorithm(environment("KEYPILOT_EXAMPLE_ALGORITHM", strconv.Itoa(int(keypilot.CryptoAlgorithmRS256))))
	payload, err := base64.RawURLEncoding.DecodeString(environment("KEYPILOT_EXAMPLE_PAYLOAD", defaultPayload))
	if err != nil {
		panic(fmt.Sprintf("decode payload: %v", err))
	}
	verifier, err := keypilot.NewVerifier(keypilot.Config{
		Issuer: issuer, JWKSURL: jwksURL,
		AllowedAlgorithms: []keypilot.CryptoAlgorithm{keypilot.CryptoAlgorithmRS256, keypilot.CryptoAlgorithmPS256},
	})
	if err != nil {
		panic(err)
	}
	result, err := verifier.VerifyBase64URL(
		context.Background(), payload, environment("KEYPILOT_EXAMPLE_SIGNATURE", defaultSignature), keyID, algorithm,
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("verification succeeded issuer=%s kid=%s algorithm=%d\n", result.Issuer, result.KeyID, result.Algorithm)
}

// environment returns an environment value or its default.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - name: environment variable name.
//   - fallback: value used when the variable is empty.
//
// Returns:
//   - string: configured or default value.
func environment(name string, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// parseAlgorithm maps a numeric environment value to a supported enum.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - value: decimal numeric algorithm code.
//
// Returns:
//   - keypilot.CryptoAlgorithm: supported algorithm enum.
func parseAlgorithm(value string) keypilot.CryptoAlgorithm {
	code, err := strconv.Atoi(value)
	if err != nil {
		panic(fmt.Sprintf("parse algorithm: %v", err))
	}
	algorithm := keypilot.CryptoAlgorithm(code)
	if !algorithm.IsSupported() {
		panic("algorithm is unsupported")
	}
	return algorithm
}
