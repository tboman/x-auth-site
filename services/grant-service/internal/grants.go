package internal

import (
	"crypto/sha256"
	"encoding/hex"
)

// HashToken returns the SHA-256 hex digest of token. Empty input returns empty string
// so a caller that fails to supply a token does not end up indexed under the digest of
// the empty string (which would be the same value for every tenant).
func HashToken(token string) string {
	if token == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// isTokenHash reports whether s looks like a SHA-256 hex digest as produced by
// HashToken (and by broker-service's hashToken): exactly 64 lowercase-or-uppercase
// hex characters. Used to validate pre-hashed token fields on POST /v1/grants.
func isTokenHash(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}
