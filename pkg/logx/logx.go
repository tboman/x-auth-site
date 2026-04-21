// Package logx wraps log/slog with a consistent JSON format and a service-name tag.
package logx

import (
	"log/slog"
	"os"
)

// New returns a JSON structured logger tagged with the service name.
// Writes to stdout (Cloud Run captures stdout into Cloud Logging).
func New(service string) *slog.Logger {
	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})
	return slog.New(handler).With("service", service)
}
