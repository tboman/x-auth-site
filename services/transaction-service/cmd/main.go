// Command transaction-service runs the orchestrator HTTP server for X-Auth for Apps.
// See services/transaction-service/README.md for endpoints and local run instructions.
package main

import (
	"context"
	"os"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/services/transaction-service/internal"
)

func main() {
	logger := logx.New("transaction-service")

	clients := internal.NewHTTPClients(
		config.Env("RISK_SERVICE_URL", "http://localhost:8081"),
		config.Env("AUTHENTICATION_SERVICE_URL", "http://localhost:8082"),
		config.Env("AUTHENTICATOR_SERVICE_URL", "http://localhost:8083"),
	)

	store := internal.NewMemStorage()
	handlers := internal.NewHandlers(store, logger, clients, clients, clients)

	addr := config.Addr(8080)
	if err := httpx.Run(context.Background(), logger, addr, handlers.Router()); err != nil {
		logger.Error("server_exit", "err", err)
		os.Exit(1)
	}
}
