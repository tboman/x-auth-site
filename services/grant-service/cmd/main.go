// Command grant-service runs the grant + audit log HTTP server.
// See services/grant-service/README.md for endpoints and local run instructions.
package main

import (
	"context"
	"os"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/services/grant-service/internal"
)

func main() {
	logger := logx.New("grant-service")
	grants := internal.NewMemGrantStore()
	audit := internal.NewMemAuditStore()
	handlers := internal.NewHandlers(grants, audit, logger)

	addr := config.Addr(8183)
	if err := httpx.Run(context.Background(), logger, addr, handlers.Router()); err != nil {
		logger.Error("server_exit", "err", err)
		os.Exit(1)
	}
}
