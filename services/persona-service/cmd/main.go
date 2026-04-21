// Command persona-service runs the persona CRUD HTTP server.
// See services/persona-service/README.md for endpoints and local run instructions.
package main

import (
	"context"
	"os"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/services/persona-service/internal"
)

func main() {
	logger := logx.New("persona-service")
	store := internal.NewMemStorage()
	handlers := internal.NewHandlers(store, logger)

	addr := config.Addr(8180)
	if err := httpx.Run(context.Background(), logger, addr, handlers.Router()); err != nil {
		logger.Error("server_exit", "err", err)
		os.Exit(1)
	}
}
