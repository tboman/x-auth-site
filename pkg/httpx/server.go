// Package httpx contains shared HTTP server helpers and middleware used by
// every X-Auth for Agents service.
package httpx

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net/http"
	"os/signal"
	"syscall"
	"time"
)

// Run starts a plaintext HTTP server on addr serving handler. It blocks until
// the process receives SIGINT or SIGTERM, then initiates a graceful shutdown.
func Run(ctx context.Context, logger *slog.Logger, addr string, handler http.Handler) error {
	return RunTLS(ctx, logger, addr, handler, nil)
}

// RunTLS is Run with an optional TLS configuration (e.g. from
// tlsx.ServerConfig). A nil tlsConf serves plaintext — the local-dev fallback;
// production passes a config carrying the service certificate and, for mTLS,
// the client CA.
func RunTLS(ctx context.Context, logger *slog.Logger, addr string, handler http.Handler, tlsConf *tls.Config) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         tlsConf,
	}

	ctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		serve := srv.ListenAndServe
		if tlsConf != nil {
			// Cert and key come from TLSConfig.Certificates.
			serve = func() error { return srv.ListenAndServeTLS("", "") }
		}
		logger.Info("http_listen", "addr", addr, "tls", tlsConf != nil)
		if err := serve(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
		close(errCh)
	}()

	select {
	case <-ctx.Done():
		logger.Info("http_shutdown_begin")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return err
		}
		logger.Info("http_shutdown_complete")
		return nil
	case err := <-errCh:
		return err
	}
}
