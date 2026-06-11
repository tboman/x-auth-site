// Package jwtx provides RS256 JWT signing, verification, and JWKS publishing
// for X-Auth services (ARCHITECTURE.md §10.1). It is intentionally stdlib-only:
// the JWS surface we need (RS256 compact serialization, fixed claim set plus
// service-specific extras, JWKS with kid-based lookup) is small enough that a
// third-party JWT dependency would cost more in version pinning than it saves.
//
// Phase 2.1 scope: access and ID tokens are RS256 JWTs signed by the issuing
// service; refresh tokens remain opaque and stored hashed. Keys come from the
// JWT_SIGNING_KEY env var (PEM) or are generated per-process for local dev.
// KMS-backed keys and 90-day rotation are a deployment concern (§10.2); the
// Verifier already supports multiple kids so rotated-out keys keep verifying.
package jwtx

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"os"
	"strings"
	"time"
)

// Leeway absorbs small clock skew between services when validating exp/iat.
const Leeway = 30 * time.Second

// Claims is the registered + X-Auth claim set from ARCHITECTURE.md §10.1.
// Zero-valued optional fields are omitted from the encoded token. Service-
// specific claims (e.g. broker's install_id / persona_id) go in the extra map
// passed to Sign.
type Claims struct {
	Sub       string `json:"sub"`
	Iss       string `json:"iss"`
	Aud       string `json:"aud,omitempty"`
	Exp       int64  `json:"exp"`
	Iat       int64  `json:"iat"`
	JTI       string `json:"jti,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Nonce     string `json:"nonce,omitempty"`

	// Standard OIDC authentication-context claims: ACR is the satisfied
	// authentication context class reference (e.g. "urn:xauth:otp:sms");
	// AMR lists the authentication methods used (RFC 8176 values, e.g.
	// ["otp","sms"]). Stamped on ID tokens minted by flows that ran a
	// second-factor interlude.
	ACR string   `json:"acr,omitempty"`
	AMR []string `json:"amr,omitempty"`
}

// Validation errors. Verify wraps these so callers can errors.Is on the cause.
var (
	ErrMalformed   = errors.New("jwtx: malformed token")
	ErrAlgorithm   = errors.New("jwtx: unexpected algorithm")
	ErrUnknownKey  = errors.New("jwtx: unknown key id")
	ErrSignature   = errors.New("jwtx: signature verification failed")
	ErrExpired     = errors.New("jwtx: token expired")
	ErrNotYetValid = errors.New("jwtx: token issued in the future")
	ErrIssuer      = errors.New("jwtx: unexpected issuer")
)

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
	Kid string `json:"kid"`
}

// -----------------------------------------------------------------------------
// Key loading
// -----------------------------------------------------------------------------

// LoadOrGenerateKey returns the RSA signing key for this process. If the env
// var named by envVar (conventionally "JWT_SIGNING_KEY") holds a PEM-encoded
// RSA private key (PKCS#1 or PKCS#8), that key is used — production sets this
// from KMS/secret storage. Otherwise a fresh 2048-bit key is generated and a
// warning is logged: ephemeral keys mean tokens do not survive a restart and
// multi-replica deployments will not verify each other's tokens.
func LoadOrGenerateKey(envVar string, logger *slog.Logger) (*rsa.PrivateKey, error) {
	if pemStr := os.Getenv(envVar); pemStr != "" {
		key, err := ParsePrivateKeyPEM([]byte(pemStr))
		if err != nil {
			return nil, fmt.Errorf("jwtx: parse %s: %w", envVar, err)
		}
		return key, nil
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("jwtx: generate key: %w", err)
	}
	logger.Warn("jwt_ephemeral_key",
		"reason", envVar+" unset; generated per-process RSA key",
		"consequence", "tokens will not verify across restarts or replicas")
	return key, nil
}

// ParsePrivateKeyPEM parses a PEM-encoded RSA private key in PKCS#1
// ("RSA PRIVATE KEY") or PKCS#8 ("PRIVATE KEY") form.
func ParsePrivateKeyPEM(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found")
	}
	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, err
		}
		key, ok := parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key is %T, want *rsa.PrivateKey", parsed)
		}
		return key, nil
	default:
		return nil, fmt.Errorf("unsupported PEM block %q", block.Type)
	}
}

// KeyID returns a stable identifier for pub: the base64url-encoded RFC 7638
// JWK thumbprint (SHA-256 over the canonical {"e","kty","n"} JSON).
func KeyID(pub *rsa.PublicKey) string {
	canonical := fmt.Sprintf(`{"e":"%s","kty":"RSA","n":"%s"}`,
		b64(bigEndianExponent(pub.E)), b64(pub.N.Bytes()))
	sum := sha256.Sum256([]byte(canonical))
	return b64(sum[:])
}

// -----------------------------------------------------------------------------
// Signer
// -----------------------------------------------------------------------------

// Signer issues RS256 JWTs under a single key. Safe for concurrent use.
type Signer struct {
	key *rsa.PrivateKey
	kid string
}

// NewSigner wraps key for signing. The kid is derived via KeyID.
func NewSigner(key *rsa.PrivateKey) *Signer {
	return &Signer{key: key, kid: KeyID(&key.PublicKey)}
}

// KID returns the key id embedded in issued tokens and published in the JWKS.
func (s *Signer) KID() string { return s.kid }

// Sign produces a compact RS256 JWS over claims merged with extra. Extra keys
// must not collide with Claims field names; collisions return an error rather
// than silently picking a winner.
func (s *Signer) Sign(claims Claims, extra map[string]any) (string, error) {
	payload, err := mergeClaims(claims, extra)
	if err != nil {
		return "", err
	}
	headerJSON, err := json.Marshal(header{Alg: "RS256", Typ: "JWT", Kid: s.kid})
	if err != nil {
		return "", err
	}
	signingInput := b64(headerJSON) + "." + b64(payload)
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("jwtx: sign: %w", err)
	}
	return signingInput + "." + b64(sig), nil
}

// JWKS returns the RFC 7517 JSON Web Key Set containing this signer's public
// key, ready to serve from a jwks endpoint.
func (s *Signer) JWKS() JWKS {
	return JWKS{Keys: []JWK{newJWK(&s.key.PublicKey, s.kid)}}
}

// JWKS is an RFC 7517 key set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK is a single RSA signing key in JWK form.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func newJWK(pub *rsa.PublicKey, kid string) JWK {
	return JWK{
		Kty: "RSA",
		Use: "sig",
		Alg: "RS256",
		Kid: kid,
		N:   b64(pub.N.Bytes()),
		E:   b64(bigEndianExponent(pub.E)),
	}
}

// -----------------------------------------------------------------------------
// Verifier
// -----------------------------------------------------------------------------

// Verifier validates RS256 JWTs against a set of public keys indexed by kid.
// Multiple keys support rotation: old keys keep verifying until dropped.
type Verifier struct {
	keys map[string]*rsa.PublicKey
	iss  string // expected issuer; empty disables the check
}

// NewVerifier builds a Verifier for the given keys. expectedIssuer of ""
// skips issuer validation.
func NewVerifier(expectedIssuer string, pubs ...*rsa.PublicKey) *Verifier {
	keys := make(map[string]*rsa.PublicKey, len(pubs))
	for _, p := range pubs {
		keys[KeyID(p)] = p
	}
	return &Verifier{keys: keys, iss: expectedIssuer}
}

// NewVerifierFromJWKS builds a Verifier from a parsed JWKS document.
func NewVerifierFromJWKS(expectedIssuer string, set JWKS) (*Verifier, error) {
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		pub, err := k.publicKey()
		if err != nil {
			return nil, fmt.Errorf("jwtx: jwk %q: %w", k.Kid, err)
		}
		keys[k.Kid] = pub
	}
	if len(keys) == 0 {
		return nil, errors.New("jwtx: JWKS contains no usable RSA keys")
	}
	return &Verifier{keys: keys, iss: expectedIssuer}, nil
}

func (k JWK) publicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e <= 1 {
		return nil, errors.New("invalid exponent")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// Verify checks the token's structure, algorithm, signature, and time window
// (exp/iat with Leeway, against now), plus issuer when the Verifier was built
// with one. It returns the standard claims and the full raw claim map (for
// service-specific extras).
func (v *Verifier) Verify(token string, now time.Time) (Claims, map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, nil, ErrMalformed
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	var h header
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return Claims{}, nil, fmt.Errorf("%w: header: %v", ErrMalformed, err)
	}
	if h.Alg != "RS256" {
		return Claims{}, nil, fmt.Errorf("%w: %q", ErrAlgorithm, h.Alg)
	}
	pub, ok := v.keys[h.Kid]
	if !ok {
		return Claims{}, nil, fmt.Errorf("%w: %q", ErrUnknownKey, h.Kid)
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, nil, fmt.Errorf("%w: signature: %v", ErrMalformed, err)
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return Claims{}, nil, ErrSignature
	}

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return Claims{}, nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}
	var raw map[string]any
	if err := json.Unmarshal(payload, &raw); err != nil {
		return Claims{}, nil, fmt.Errorf("%w: payload: %v", ErrMalformed, err)
	}

	if claims.Exp != 0 && now.After(time.Unix(claims.Exp, 0).Add(Leeway)) {
		return Claims{}, nil, ErrExpired
	}
	if claims.Iat != 0 && time.Unix(claims.Iat, 0).After(now.Add(Leeway)) {
		return Claims{}, nil, ErrNotYetValid
	}
	if v.iss != "" && claims.Iss != v.iss {
		return Claims{}, nil, fmt.Errorf("%w: %q", ErrIssuer, claims.Iss)
	}
	return claims, raw, nil
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

func mergeClaims(claims Claims, extra map[string]any) ([]byte, error) {
	if len(extra) == 0 {
		return json.Marshal(claims)
	}
	base, err := json.Marshal(claims)
	if err != nil {
		return nil, err
	}
	merged := make(map[string]any, len(extra)+8)
	if err := json.Unmarshal(base, &merged); err != nil {
		return nil, err
	}
	for k, val := range extra {
		if _, exists := merged[k]; exists {
			return nil, fmt.Errorf("jwtx: extra claim %q collides with standard claim", k)
		}
		merged[k] = val
	}
	return json.Marshal(merged)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// bigEndianExponent encodes the public exponent as a minimal big-endian byte
// slice, as JWK requires.
func bigEndianExponent(e int) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(e))
	i := 0
	for i < 7 && buf[i] == 0 {
		i++
	}
	return buf[i:]
}
