package internal

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// randToken returns a URL-safe random identifier with n bytes of entropy.
func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failure is not recoverable; the caller can't make a safe
		// token without it.
		panic("id-service: crypto/rand failed: " + err.Error())
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// decodeBase64 tolerates the four base64 alphabets wallets and browsers emit for
// a DeviceResponse / vp_token (raw vs padded, URL vs standard).
func decodeBase64(s string) ([]byte, error) {
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("not valid base64 in any common alphabet")
}
