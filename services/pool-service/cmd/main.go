// Command pool-service runs the X-Auth for Agents pool-service HTTP server.
// See REQUIREMENTS.md §3 & §4 for scope.
package main

import (
	"context"
	"os"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/services/pool-service/internal"
)

func main() {
	logger := logx.New("pool-service")

	storage := internal.NewMemStorage()
	srv := internal.NewServer(storage, logger)

	// Wrap the service handler with shared middleware (recover + structured logging).
	handler := httpx.Recover(logger)(httpx.Logging(logger)(srv.Handler()))

	addr := config.Addr(8181)
	if err := httpx.Run(context.Background(), logger, addr, handler); err != nil {
		logger.Error("server_failed", "err", err)
		os.Exit(1)
	}
}
