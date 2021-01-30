package ftauth

import "fmt"

// KeyStore exchanges private key data with a backend keychain.
// Implementations will vary by client, but all should be encrypted
// or reasonably protected against attacks.
type KeyStore interface {
	Save(key, value []byte) *KeyStoreError
	Get(key []byte) ([]byte, *KeyStoreError)
}

// KeyStoreError represents an error in retrieving or saving keys to
// the keychain. It provides a common error type across many platform
// implementations.
type KeyStoreError struct {
	Code    KeyStoreErrorCode
	Details string
}

func (err *KeyStoreError) Error() string {
	return fmt.Sprintf("%s: %s", err.Code.Description(), err.Details)
}

// KeyStoreErrorCode represents the different error types expected from
// a KeyStore implementation.
type KeyStoreErrorCode int

// KeyStoreErrorCodes
const (
	KeyStoreErrorCodeUnknown KeyStoreErrorCode = iota // an unknown error occurred
	KeyStoreErrorAccess                               // error accessing the keychain (e.g. i/o error)
	KeyStoreErrorCodeKey                              // an error accessing the key (i.e. not found)
)

// Description provides a human-readable description of the error code.
func (code KeyStoreErrorCode) Description() string {
	switch code {
	case KeyStoreErrorAccess:
		return "The keychain is not accessible."
	case KeyStoreErrorCodeKey:
		return "The key was not found."
	default:
		return "An unknown error occurred."
	}
}
