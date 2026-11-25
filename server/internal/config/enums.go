/*
Description: Defines stable numeric server configuration enums.
Author: vectorshi
Created: 2026-11-25
*/
package config

// StorageType selects the server persistence implementation.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters: None.
// Returns: None.
type StorageType int

const (
	StorageTypeJSONFile StorageType = 1
	StorageTypeSQLite   StorageType = 2
)

// IsValid reports whether the storage type is supported.
//
// Author: vectorshi
// Created: 2026-11-25
// Parameters:
//   - storageType: StorageType receiver to validate.
//
// Returns:
//   - bool: true when the storage type is supported.
func (storageType StorageType) IsValid() bool {
	return storageType == StorageTypeJSONFile || storageType == StorageTypeSQLite
}
