package internal

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/golang-jwt/jwt/v5"
)

// DefaultMDSURL is the FIDO Alliance production Metadata Service v3 BLOB endpoint.
const DefaultMDSURL = metadata.ProductionMDSURL

// allowedJWTMethods is the set of signing algorithms the MDS BLOB may use. The
// production blob is RS256; the conformance suite uses ES256. Pinning the set
// closes the alg-confusion / "none" attack surface.
var allowedJWTMethods = []string{"RS256", "RS384", "RS512", "PS256", "ES256", "ES384", "ES512"}

// Fetcher downloads and verifies the MDS BLOB. The trust anchor is the FIDO
// Alliance MDS root (metadata.ProductionMDSRoot) unless MDS_ROOT_CERT_FILE
// overrides it. Safe for concurrent use.
type Fetcher struct {
	url    string
	client *http.Client
	roots  *x509.CertPool
}

// NewFetcher builds a Fetcher. rootCertFile (MDS_ROOT_CERT_FILE) is an optional
// path to a PEM-encoded root CA that replaces the embedded production root.
func NewFetcher(url, rootCertFile string) (*Fetcher, error) {
	roots, err := loadRoots(rootCertFile)
	if err != nil {
		return nil, err
	}
	if url == "" {
		url = DefaultMDSURL
	}
	return &Fetcher{
		url:    url,
		client: &http.Client{Timeout: 30 * time.Second},
		roots:  roots,
	}, nil
}

// Fetch downloads the raw compact-JWS BLOB.
func (f *Fetcher) Fetch(ctx context.Context) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, f.url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("mds: fetch %s: status %d", f.url, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20)) // 32 MiB ceiling
	if err != nil {
		return nil, err
	}
	return body, nil
}

// VerifyAndParse validates the BLOB's JWS signature against an x5c chain rooted
// in the pinned FIDO root, then decodes the payload into our lean structs (see
// mdspayload.go for why we don't reuse the metadata package's payload type).
func (f *Fetcher) VerifyAndParse(raw []byte) (*mdsPayload, error) {
	token := strings.TrimSpace(string(raw))

	_, err := jwt.Parse(token, f.keyFunc, jwt.WithValidMethods(allowedJWTMethods))
	if err != nil {
		return nil, fmt.Errorf("mds: verify signature: %w", err)
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("mds: blob is not a compact JWS")
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("mds: decode payload: %w", err)
	}
	var payload mdsPayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return nil, fmt.Errorf("mds: unmarshal payload: %w", err)
	}
	return &payload, nil
}

// keyFunc validates the x5c chain in the JWS header against the pinned root and
// returns the leaf public key for jwt to verify the signature with. CRL/OCSP
// revocation is intentionally not checked here (network dependency) — see the
// README hardening note.
func (f *Fetcher) keyFunc(t *jwt.Token) (interface{}, error) {
	x5c, ok := t.Header["x5c"].([]interface{})
	if !ok || len(x5c) == 0 {
		return nil, errors.New("mds: missing x5c certificate chain")
	}
	certs := make([]*x509.Certificate, 0, len(x5c))
	for _, item := range x5c {
		b64, ok := item.(string)
		if !ok {
			return nil, errors.New("mds: malformed x5c entry")
		}
		der, err := base64.StdEncoding.DecodeString(b64)
		if err != nil {
			return nil, fmt.Errorf("mds: decode x5c: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("mds: parse x5c: %w", err)
		}
		certs = append(certs, cert)
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}
	leaf := certs[0]
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:         f.roots,
		Intermediates: intermediates,
	}); err != nil {
		return nil, fmt.Errorf("mds: chain verification failed: %w", err)
	}
	return leaf.PublicKey, nil
}

// loadRoots builds the trust pool. A PEM file overrides the embedded production
// root (handy for the conformance suite or air-gapped pinning).
func loadRoots(rootCertFile string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if rootCertFile != "" {
		pem, err := os.ReadFile(rootCertFile)
		if err != nil {
			return nil, fmt.Errorf("mds: read root cert file: %w", err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("mds: root cert file contained no certificates")
		}
		return pool, nil
	}
	der, err := base64.StdEncoding.DecodeString(metadata.ProductionMDSRoot)
	if err != nil {
		return nil, fmt.Errorf("mds: decode embedded root: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("mds: parse embedded root: %w", err)
	}
	pool.AddCert(cert)
	return pool, nil
}
