/*
Description: Implements KeyPilot HTTP routing, authentication, JSON handling, and response mapping.
Author: vectorshi
Created: 2026-11-25
*/
package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/codepunk-gm/keypilot/server/internal/keyregistry"
)

const maxRequestBodyBytes int64 = 1 << 20

type requestIDContextKey struct{}

// Handler serves the public JWKS and administration APIs.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type Handler struct {
	service        *keyregistry.Service
	adminID        string
	adminTokenHash [32]byte
	jwksMaxAge     int
}

// createIssuerRequest describes the issuer creation request body.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type createIssuerRequest struct {
	Issuer      string `json:"issuer"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
}

// importKeyRequest describes the key import request envelope.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type importKeyRequest struct {
	Description string          `json:"description,omitempty"`
	JWK         json.RawMessage `json:"jwk"`
}

// updateKeyStatusRequest describes the numeric key status update request.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type updateKeyStatusRequest struct {
	Status keyregistry.KeyStatus `json:"status"`
	Reason string                `json:"reason,omitempty"`
}

// itemList describes a JSON list response.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type itemList[T any] struct {
	Items []T `json:"items"`
}

// errorEnvelope describes the stable JSON API error response.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type errorEnvelope struct {
	Error errorBody `json:"error"`
}

// errorBody describes one numeric API error.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type errorBody struct {
	Code      keyregistry.APIErrorCode `json:"code"`
	Message   string                   `json:"message"`
	RequestID string                   `json:"requestId"`
}

// New creates the complete KeyPilot HTTP handler.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - service: key registry service.
//   - adminID: stable administration identity written to audit records.
//   - adminToken: administration bearer token.
//   - jwksMaxAge: public JWKS cache duration in seconds.
//
// Returns:
//   - http.Handler: configured request handler.
func New(service *keyregistry.Service, adminID string, adminToken string, jwksMaxAge int) http.Handler {
	handler := &Handler{service: service, adminID: adminID, adminTokenHash: sha256.Sum256([]byte(adminToken)), jwksMaxAge: jwksMaxAge}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", handler.getHealth)
	mux.HandleFunc("GET /readyz", handler.getReady)
	mux.HandleFunc("GET /v1/issuers/{issuer}/.well-known/jwks.json", handler.getIssuerJWKS)
	mux.Handle("GET /admin/v1/audits", handler.requireAdmin(http.HandlerFunc(handler.listAudits)))
	mux.Handle("POST /admin/v1/issuers", handler.requireAdmin(http.HandlerFunc(handler.createIssuer)))
	mux.Handle("GET /admin/v1/issuers", handler.requireAdmin(http.HandlerFunc(handler.listIssuers)))
	mux.Handle("GET /admin/v1/issuers/{issuer}", handler.requireAdmin(http.HandlerFunc(handler.getIssuer)))
	mux.Handle("POST /admin/v1/issuers/{issuer}/keys", handler.requireAdmin(http.HandlerFunc(handler.importKey)))
	mux.Handle("GET /admin/v1/issuers/{issuer}/keys", handler.requireAdmin(http.HandlerFunc(handler.listKeys)))
	mux.Handle("GET /admin/v1/issuers/{issuer}/keys/{kid}", handler.requireAdmin(http.HandlerFunc(handler.getKey)))
	mux.Handle("PATCH /admin/v1/issuers/{issuer}/keys/{kid}/status", handler.requireAdmin(http.HandlerFunc(handler.updateKeyStatus)))
	return handler.withRequestID(mux)
}

// getHealth returns the liveness response.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//
// Returns: None.
func (handler *Handler) getHealth(response http.ResponseWriter, request *http.Request) {
	writeJSON(response, http.StatusOK, map[string]string{"status": "ok"})
}

// getReady returns readiness only when the configured persistence store is readable.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//
// Returns: None.
func (handler *Handler) getReady(response http.ResponseWriter, request *http.Request) {
	if err := handler.service.CheckReady(request.Context()); err != nil {
		handler.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, map[string]string{"status": "ready"})
}

// createIssuer validates and creates an issuer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//
// Returns: None.
func (handler *Handler) createIssuer(response http.ResponseWriter, request *http.Request) {
	var body createIssuerRequest
	if err := decodeJSON(response, request, &body); err != nil {
		handler.writeAuditedError(response, request, keyregistry.AuditActionCreateIssuer, body.Issuer, "", keyregistry.NewDomainError(keyregistry.APIErrorValidation, err.Error(), err))
		return
	}
	issuer, err := handler.service.CreateIssuer(request.Context(), handler.auditContext(request, handler.adminID), body.Issuer, body.DisplayName, body.Description)
	if err != nil {
		handler.writeAuditedError(response, request, keyregistry.AuditActionCreateIssuer, body.Issuer, "", err)
		return
	}
	writeJSON(response, http.StatusCreated, issuer)
}

// listAudits returns recent administration audit records.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//
// Returns: None.
func (handler *Handler) listAudits(response http.ResponseWriter, request *http.Request) {
	limit := 100
	if rawLimit := strings.TrimSpace(request.URL.Query().Get("limit")); rawLimit != "" {
		parsedLimit, err := strconv.Atoi(rawLimit)
		if err != nil {
			handler.writeError(response, request, keyregistry.NewDomainError(keyregistry.APIErrorValidation, "audit limit must be an integer", err))
			return
		}
		limit = parsedLimit
	}
	audits, err := handler.service.ListAudits(request.Context(), request.URL.Query().Get("issuer"), limit)
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, itemList[keyregistry.AuditRecord]{Items: audits})
}

// listIssuers returns all issuers.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//
// Returns: None.
func (handler *Handler) listIssuers(response http.ResponseWriter, request *http.Request) {
	issuers, err := handler.service.ListIssuers(request.Context())
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, itemList[keyregistry.Issuer]{Items: issuers})
}

// getIssuer returns one issuer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//
// Returns: None.
func (handler *Handler) getIssuer(response http.ResponseWriter, request *http.Request) {
	issuer, err := handler.service.GetIssuer(request.Context(), request.PathValue("issuer"))
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, issuer)
}

// importKey validates and imports a public RSA JWK.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//
// Returns: None.
func (handler *Handler) importKey(response http.ResponseWriter, request *http.Request) {
	var body importKeyRequest
	if err := decodeJSON(response, request, &body); err != nil {
		handler.writeAuditedError(response, request, keyregistry.AuditActionImportKey, request.PathValue("issuer"), "", keyregistry.NewDomainError(keyregistry.APIErrorValidation, err.Error(), err))
		return
	}
	jwk, err := decodePublicJWK(body.JWK)
	if err != nil {
		handler.writeAuditedError(response, request, keyregistry.AuditActionImportKey, request.PathValue("issuer"), "", err)
		return
	}
	key, err := handler.service.ImportKey(request.Context(), handler.auditContext(request, handler.adminID), request.PathValue("issuer"), jwk, body.Description)
	if err != nil {
		handler.writeAuditedError(response, request, keyregistry.AuditActionImportKey, request.PathValue("issuer"), jwk.KeyID, err)
		return
	}
	writeJSON(response, http.StatusCreated, key)
}

// listKeys returns all keys for an issuer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//
// Returns: None.
func (handler *Handler) listKeys(response http.ResponseWriter, request *http.Request) {
	keys, err := handler.service.ListKeys(request.Context(), request.PathValue("issuer"))
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, itemList[keyregistry.VerificationKey]{Items: keys})
}

// getKey returns one key for an issuer.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//
// Returns: None.
func (handler *Handler) getKey(response http.ResponseWriter, request *http.Request) {
	key, err := handler.service.GetKey(request.Context(), request.PathValue("issuer"), request.PathValue("kid"))
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	writeJSON(response, http.StatusOK, key)
}

// updateKeyStatus applies a numeric key lifecycle transition.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//
// Returns: None.
func (handler *Handler) updateKeyStatus(response http.ResponseWriter, request *http.Request) {
	var body updateKeyStatusRequest
	if err := decodeJSON(response, request, &body); err != nil {
		handler.writeAuditedError(response, request, keyregistry.AuditActionUpdateKeyState, request.PathValue("issuer"), request.PathValue("kid"), keyregistry.NewDomainError(keyregistry.APIErrorValidation, err.Error(), err))
		return
	}
	key, err := handler.service.UpdateKeyStatus(
		request.Context(), handler.auditContext(request, handler.adminID), request.PathValue("issuer"), request.PathValue("kid"), body.Status, body.Reason,
	)
	if err != nil {
		handler.writeAuditedError(response, request, keyregistry.AuditActionUpdateKeyState, request.PathValue("issuer"), request.PathValue("kid"), err)
		return
	}
	writeJSON(response, http.StatusOK, key)
}

// getIssuerJWKS returns a stable ordered and cacheable JWK Set.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//
// Returns: None.
func (handler *Handler) getIssuerJWKS(response http.ResponseWriter, request *http.Request) {
	jwkSet, err := handler.service.GetJWKSet(request.Context(), request.PathValue("issuer"))
	if err != nil {
		handler.writeError(response, request, err)
		return
	}
	body, err := json.Marshal(jwkSet)
	if err != nil {
		handler.writeError(response, request, keyregistry.NewDomainError(keyregistry.APIErrorInternal, "JWK Set could not be encoded", err))
		return
	}
	digest := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(digest[:]) + `"`
	response.Header().Set("ETag", etag)
	response.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(handler.jwksMaxAge))
	if request.Header.Get("If-None-Match") == etag {
		response.WriteHeader(http.StatusNotModified)
		return
	}
	response.Header().Set("Content-Type", "application/jwk-set+json")
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(body)
}

// requireAdmin enforces the configured administration bearer token.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - next: protected HTTP handler.
//
// Returns:
//   - http.Handler: authentication middleware.
func (handler *Handler) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		authorization := request.Header.Get("Authorization")
		const prefix = "Bearer "
		if !strings.HasPrefix(authorization, prefix) {
			handler.writeAuditedError(response, request, keyregistry.AuditActionAuthentication, request.PathValue("issuer"), request.PathValue("kid"), keyregistry.NewDomainError(keyregistry.APIErrorUnauthorized, "administration token is required", nil))
			return
		}
		providedHash := sha256.Sum256([]byte(strings.TrimSpace(strings.TrimPrefix(authorization, prefix))))
		if subtle.ConstantTimeCompare(providedHash[:], handler.adminTokenHash[:]) != 1 {
			handler.writeAuditedError(response, request, keyregistry.AuditActionAuthentication, request.PathValue("issuer"), request.PathValue("kid"), keyregistry.NewDomainError(keyregistry.APIErrorUnauthorized, "administration token is invalid", nil))
			return
		}
		next.ServeHTTP(response, request)
	})
}

// withRequestID applies or creates the request correlation identifier.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - next: next HTTP handler.
//
// Returns:
//   - http.Handler: request identifier middleware.
func (handler *Handler) withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		identifier := strings.TrimSpace(request.Header.Get("X-Request-ID"))
		if identifier == "" || len(identifier) > 128 {
			identifier = newRequestID()
		}
		response.Header().Set("X-Request-ID", identifier)
		contextWithID := context.WithValue(request.Context(), requestIDContextKey{}, identifier)
		next.ServeHTTP(response, request.WithContext(contextWithID))
	})
}

// writeError maps a domain error to its HTTP status and JSON response.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//   - err: error to map.
//
// Returns: None.
func (handler *Handler) writeError(response http.ResponseWriter, request *http.Request, err error) {
	domainError := domainErrorFrom(err)
	writeJSON(response, statusForCode(domainError.Code), errorEnvelope{Error: errorBody{
		Code: domainError.Code, Message: domainError.Message, RequestID: requestID(request.Context()),
	}})
}

// writeAuditedError records an administration failure before writing the original error response.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - request: HTTP request.
//   - action: attempted administration action.
//   - issuer: optional issuer identifier.
//   - keyID: optional key identifier.
//   - err: original domain error.
//
// Returns: None.
func (handler *Handler) writeAuditedError(response http.ResponseWriter, request *http.Request, action keyregistry.AuditAction, issuer string, keyID string, err error) {
	domainError := domainErrorFrom(err)
	actor := handler.adminID
	if action == keyregistry.AuditActionAuthentication {
		actor = "anonymous"
	}
	_ = handler.service.RecordFailure(request.Context(), handler.auditContext(request, actor), action, issuer, keyID, domainError.Code, domainError.Message)
	handler.writeError(response, request, domainError)
}

// auditContext extracts bounded request metadata for administration audit records.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - request: current HTTP request.
//   - actor: authenticated or anonymous actor identifier.
//
// Returns:
//   - keyregistry.AuditContext: request metadata safe for audit persistence.
func (handler *Handler) auditContext(request *http.Request, actor string) keyregistry.AuditContext {
	clientIP := request.RemoteAddr
	if host, _, err := net.SplitHostPort(request.RemoteAddr); err == nil {
		clientIP = host
	}
	return keyregistry.AuditContext{
		RequestID: requestID(request.Context()), Actor: actor, ClientIP: clientIP, UserAgent: request.UserAgent(),
	}
}

// domainErrorFrom normalizes arbitrary errors into the stable domain error contract.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - err: error to normalize.
//
// Returns:
//   - *keyregistry.DomainError: existing or synthesized domain error.
func domainErrorFrom(err error) *keyregistry.DomainError {
	domainError := &keyregistry.DomainError{}
	if !errors.As(err, &domainError) {
		return keyregistry.NewDomainError(keyregistry.APIErrorInternal, "internal server error", err)
	}
	return domainError
}

// decodeJSON decodes one strict JSON object and rejects additional content.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer used to apply the body size limit.
//   - request: HTTP request containing JSON.
//   - destination: target value receiving decoded JSON.
//
// Returns:
//   - error: body size, syntax, unknown field, or trailing content error.
func decodeJSON(response http.ResponseWriter, request *http.Request, destination any) error {
	request.Body = http.MaxBytesReader(response, request.Body, maxRequestBodyBytes)
	decoder := json.NewDecoder(request.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid JSON request: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("request body must contain one JSON object")
	}
	return nil
}

// decodePublicJWK rejects private parameters and decodes one strict RSA public JWK.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - content: raw JWK JSON object.
//
// Returns:
//   - keyregistry.RSAPublicJWK: decoded public JWK.
//   - error: private key, invalid field, or JSON error.
func decodePublicJWK(content json.RawMessage) (keyregistry.RSAPublicJWK, error) {
	if len(content) == 0 {
		return keyregistry.RSAPublicJWK{}, keyregistry.NewDomainError(keyregistry.APIErrorInvalidJWK, "JWK is required", nil)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(content, &fields); err != nil {
		return keyregistry.RSAPublicJWK{}, keyregistry.NewDomainError(keyregistry.APIErrorInvalidJWK, "JWK must be a JSON object", err)
	}
	for _, privateField := range []string{"d", "p", "q", "dp", "dq", "qi", "oth"} {
		if _, exists := fields[privateField]; exists {
			return keyregistry.RSAPublicJWK{}, keyregistry.NewDomainError(keyregistry.APIErrorPrivateKeyNotAllowed, "private key parameters are not allowed", nil)
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(content)))
	decoder.DisallowUnknownFields()
	var jwk keyregistry.RSAPublicJWK
	if err := decoder.Decode(&jwk); err != nil {
		return keyregistry.RSAPublicJWK{}, keyregistry.NewDomainError(keyregistry.APIErrorInvalidJWK, "JWK fields are invalid", err)
	}
	return jwk, nil
}

// writeJSON writes one JSON response.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - response: HTTP response writer.
//   - status: HTTP response status.
//   - body: JSON response body.
//
// Returns: None.
func writeJSON(response http.ResponseWriter, status int, body any) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(body)
}

// statusForCode maps a stable API error code to an HTTP status.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - code: stable API error code.
//
// Returns:
//   - int: HTTP status code.
func statusForCode(code keyregistry.APIErrorCode) int {
	switch code {
	case keyregistry.APIErrorValidation, keyregistry.APIErrorInvalidJWK, keyregistry.APIErrorPrivateKeyNotAllowed, keyregistry.APIErrorAlgorithmNotAllowed:
		return http.StatusBadRequest
	case keyregistry.APIErrorUnauthorized:
		return http.StatusUnauthorized
	case keyregistry.APIErrorIssuerNotFound, keyregistry.APIErrorKeyNotFound:
		return http.StatusNotFound
	case keyregistry.APIErrorIssuerAlreadyExists, keyregistry.APIErrorKeyAlreadyExists, keyregistry.APIErrorInvalidKeyTransition:
		return http.StatusConflict
	case keyregistry.APIErrorStorageUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// requestID returns the current request correlation identifier.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - ctx: request context.
//
// Returns:
//   - string: request identifier or an empty string when unavailable.
func requestID(ctx context.Context) string {
	identifier, _ := ctx.Value(requestIDContextKey{}).(string)
	return identifier
}

// newRequestID creates a cryptographically random hexadecimal request identifier.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns:
//   - string: request identifier.
func newRequestID() string {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return fmt.Sprintf("fallback-%x", sha256.Sum256([]byte(err.Error())))
	}
	return hex.EncodeToString(buffer)
}
