// Package tlsx builds TLS configurations for X-Auth services from environment
// variables, implementing ARCHITECTURE.md §10.3 transport security:
// service-to-service traffic runs over mutual TLS with per-service
// certificates.
//
// Env contract (all optional as a group, but partial configuration is an error
// — a service must never silently fall back to plaintext because one path was
// mistyped):
//
//	TLS_CERT_FILE       PEM certificate this service presents (server and client side)
//	TLS_KEY_FILE        PEM private key for TLS_CERT_FILE
//	TLS_CLIENT_CA_FILE  CA bundle; when set the server REQUIRES and verifies
//	                    client certificates (mTLS)
//	TLS_CA_FILE         CA bundle used to verify sister services when dialing out
//
// With none of the vars set, both ServerConfig and ClientConfig return nil and
// services run plaintext — the local-dev fallback, mirroring the PG_DSN and
// JWT_SIGNING_KEY patterns. Production (service mesh or direct) sets all four.
package tlsx

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

// Env var names. Exported so tests and deploy tooling reference one source.
const (
	EnvCertFile     = "TLS_CERT_FILE"
	EnvKeyFile      = "TLS_KEY_FILE"
	EnvClientCAFile = "TLS_CLIENT_CA_FILE"
	EnvCAFile       = "TLS_CA_FILE"
)

// ErrPartialConfig indicates that some but not all of a required env var group
// is set; the service must exit rather than guess.
var ErrPartialConfig = errors.New("tlsx: partial TLS configuration")

// ServerConfig builds the server-side TLS config from the environment.
//
//   - Neither TLS_CERT_FILE nor TLS_KEY_FILE set: returns (nil, nil) and the
//     caller serves plaintext (local dev). A warning is logged so a
//     misconfigured production deploy is visible.
//   - Exactly one of the pair set: ErrPartialConfig.
//   - Both set: TLS ≥1.2. If TLS_CLIENT_CA_FILE is also set, client
//     certificates are required and verified against it (mTLS).
func ServerConfig(logger *slog.Logger) (*tls.Config, error) {
	certFile, keyFile := os.Getenv(EnvCertFile), os.Getenv(EnvKeyFile)
	if certFile == "" && keyFile == "" {
		logger.Warn("tls_disabled", "reason", EnvCertFile+"/"+EnvKeyFile+" unset; serving plaintext")
		return nil, nil
	}
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("%w: %s and %s must both be set", ErrPartialConfig, EnvCertFile, EnvKeyFile)
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("tlsx: load server keypair: %w", err)
	}
	conf := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
	}
	if caFile := os.Getenv(EnvClientCAFile); caFile != "" {
		pool, err := loadCertPool(caFile)
		if err != nil {
			return nil, fmt.Errorf("tlsx: load client CA: %w", err)
		}
		conf.ClientCAs = pool
		conf.ClientAuth = tls.RequireAndVerifyClientCert
		logger.Info("tls_mtls_enabled", "client_ca", caFile)
	} else {
		logger.Info("tls_enabled", "mode", "server-only (no client cert verification)")
	}
	return conf, nil
}

// ClientConfig builds the TLS config services use when calling sister
// services. Returns (nil, nil) when nothing is configured (plaintext dev).
// TLS_CA_FILE supplies the trust anchor for verifying the callee; the
// TLS_CERT_FILE/TLS_KEY_FILE pair, when present, is presented as the client
// certificate so the callee's mTLS check passes.
func ClientConfig(logger *slog.Logger) (*tls.Config, error) {
	caFile := os.Getenv(EnvCAFile)
	certFile, keyFile := os.Getenv(EnvCertFile), os.Getenv(EnvKeyFile)

	if caFile == "" && certFile == "" && keyFile == "" {
		return nil, nil
	}
	if certFile != "" && keyFile == "" || certFile == "" && keyFile != "" {
		return nil, fmt.Errorf("%w: %s and %s must both be set", ErrPartialConfig, EnvCertFile, EnvKeyFile)
	}

	conf := &tls.Config{MinVersion: tls.VersionTLS12}
	if caFile != "" {
		pool, err := loadCertPool(caFile)
		if err != nil {
			return nil, fmt.Errorf("tlsx: load CA: %w", err)
		}
		conf.RootCAs = pool
	}
	if certFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("tlsx: load client keypair: %w", err)
		}
		conf.Certificates = []tls.Certificate{cert}
	}
	logger.Info("tls_client_enabled", "ca", caFile, "client_cert", certFile != "")
	return conf, nil
}

// Transport returns an http.RoundTripper for inter-service calls: a clone of
// http.DefaultTransport carrying the ClientConfig TLS settings. With no TLS
// configured it returns http.DefaultTransport unchanged.
func Transport(logger *slog.Logger) (http.RoundTripper, error) {
	conf, err := ClientConfig(logger)
	if err != nil {
		return nil, err
	}
	if conf == nil {
		return http.DefaultTransport, nil
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = conf
	return t, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pemBytes) {
		return nil, fmt.Errorf("no certificates parsed from %s", path)
	}
	return pool, nil
}
