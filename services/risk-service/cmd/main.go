// risk-service is the internal risk scoring and policy engine for X-Auth for Apps.
// It ingests identity signals (device, behavior, network, user) plus resource
// sensitivity, aggregates a weighted risk score, evaluates tenant policies, and
// returns a risk tier (low / medium / high) with a policy decision.
//
// See ARCHITECTURE.md §4.2 and §7 for the source-of-truth request/response
// shapes, scorers, weights, and tier thresholds. See services/risk-service/README.md
// for local-run and cURL examples.
package main

import (
	"context"
	"os"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/services/risk-service/internal"
)

func main() {
	logger := logx.New("risk-service")

	store := internal.NewMemStorage()
	handlers := internal.NewHandlers(store, logger)

	addr := config.Addr(8081)
	if err := httpx.Run(context.Background(), logger, addr, handlers.Router()); err != nil {
		logger.Error("server_exited_with_error", "err", err)
		os.Exit(1)
	}
}
