/*
Description: Defines the minimal storage boundary required by the key registry service.
Author: vectorshi
Created: 2026-11-25
*/
package keyregistry

import "context"

// Store defines atomic persistence operations used by the key registry.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type Store interface {
	CreateIssuer(context.Context, Issuer, AuditRecord) error
	ListIssuers(context.Context) ([]Issuer, error)
	GetIssuer(context.Context, string) (Issuer, error)
	CreateKey(context.Context, VerificationKey, AuditRecord) error
	ListKeys(context.Context, string) ([]VerificationKey, error)
	GetKey(context.Context, string, string) (VerificationKey, error)
	UpdateKey(context.Context, VerificationKey, AuditRecord) error
	AppendAudit(context.Context, AuditRecord) error
	ListAudits(context.Context) ([]AuditRecord, error)
}
