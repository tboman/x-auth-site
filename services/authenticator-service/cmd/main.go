// Command authenticator-service is the internal authenticator CRUD + challenge
// dispatch/verify service for X-Auth for Apps.
package main

import (
	"context"
	"os"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/services/authenticator-service/internal"
)

func main() {
	log := logx.New("authenticator-service")
	store := internal.NewStore(nil)
	registry := internal.NewRegistry(log)
	handler := internal.Router(log, store, registry)

	if err := httpx.Run(context.Background(), log, config.Addr(8083), handler); err != nil {
		log.Error("server_exit", "err", err)
		os.Exit(1)
	}
}
