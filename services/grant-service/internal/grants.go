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
