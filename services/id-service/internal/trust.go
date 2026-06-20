package internal

import (
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Trust modes for the mDL issuer (IACA) chain.
const (
	TrustModeStrict   = "strict"              // require a chain to a configured root
	TrustModeInsecure = "insecure-accept-any" // parse + extract, flag untrusted (demo/dev)
)

// TrustStore anchors mDL issuer signing certificates. Production loads the
// issuing authorities' IACA roots (env-supplied; AAMVA/state roots are
// membership-gated and intentionally not bundled). In insecure-accept-any mode
// an unanchored chain still yields claims, flagged issuer_trusted=false.
type TrustStore struct {
	mode   string
	roots  *x509.CertPool
	count  int
	logger *slog.Logger
}

// NewTrustStore builds the store from TRUST_MODE plus optional PEM sources:
// rootFile (IACA_ROOT_CERT_FILE) and rootsDir (IACA_ROOTS_DIR, *.pem/*.crt).
func NewTrustStore(mode, rootFile, rootsDir string, logger *slog.Logger) (*TrustStore, error) {
	if mode == "" {
		mode = TrustModeStrict
	}
	if mode != TrustModeStrict && mode != TrustModeInsecure {
		return nil, fmt.Errorf("trust: invalid TRUST_MODE %q (want %q or %q)", mode, TrustModeStrict, TrustModeInsecure)
	}

	pool := x509.NewCertPool()
	count := 0
	addPEM := func(path string) error {
		pem, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("trust: read %s: %w", path, err)
		}
		before := len(pool.Subjects()) //nolint:staticcheck // count delta only
		if pool.AppendCertsFromPEM(pem) && len(pool.Subjects()) > before {
			count++
		}
		return nil
	}

	if rootFile != "" {
		if err := addPEM(rootFile); err != nil {
			return nil, err
		}
	}
	if rootsDir != "" {
		entries, err := os.ReadDir(rootsDir)
		if err != nil {
			return nil, fmt.Errorf("trust: read dir %s: %w", rootsDir, err)
		}
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			ext := strings.ToLower(filepath.Ext(e.Name()))
			if ext != ".pem" && ext != ".crt" && ext != ".cer" {
				continue
			}
			if err := addPEM(filepath.Join(rootsDir, e.Name())); err != nil {
				return nil, err
			}
		}
	}

	if mode == TrustModeStrict && count == 0 {
		logger.Warn("trust_no_roots",
			"mode", mode,
			"consequence", "no IACA roots configured; every issuer chain will fail to anchor",
			"hint", "set IACA_ROOT_CERT_FILE / IACA_ROOTS_DIR, or TRUST_MODE=insecure-accept-any for demos")
	}
	if mode == TrustModeInsecure {
		logger.Warn("trust_insecure_mode",
			"mode", mode,
			"consequence", "unanchored issuer chains are accepted and flagged issuer_trusted=false")
	}

	return &TrustStore{mode: mode, roots: pool, count: count, logger: logger}, nil
}

// Mode reports the configured trust mode.
func (t *TrustStore) Mode() string { return t.mode }

// RootCount reports how many issuer roots were loaded.
func (t *TrustStore) RootCount() int { return t.count }

// Verify checks the issuer signing-cert chain (leaf first). It returns whether
// the chain anchored to a configured root, the leaf certificate, and an error.
// In insecure-accept-any mode an unanchored chain returns (false, leaf, nil) so
// the claims still parse; in strict mode it returns an error.
func (t *TrustStore) Verify(certs []*x509.Certificate) (bool, *x509.Certificate, error) {
	if len(certs) == 0 {
		return false, nil, errors.New("trust: empty certificate chain")
	}
	leaf := certs[0]
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         t.roots,
		Intermediates: inter,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err == nil {
		return true, leaf, nil
	}
	if t.mode == TrustModeInsecure {
		t.logger.Warn("issuer_chain_untrusted", "err", err.Error(), "subject", leaf.Subject.String())
		return false, leaf, nil
	}
	return false, leaf, fmt.Errorf("trust: chain verification failed: %w", err)
}
