// authentication-service is the public OIDC provider for X-Auth for Apps.
// It owns users, sessions, tokens, and OIDC endpoints (discovery, authorize,
// token, userinfo, revoke), plus phase-1 social-login stubs for google,
// github, and microsoft.
//
// See ARCHITECTURE.md §4.3 for the source-of-truth contract and
// services/authentication-service/README.md for the full endpoint list.
package main

import (
	"context"
	"os"

	"github.com/xentranet/x-auth/pkg/config"
	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/logx"
	"github.com/xentranet/x-auth/services/authentication-service/internal"
)

func main() {
	logger := logx.New("authentication-service")

	authenticatorURL := config.Env("AUTHENTICATOR_SERVICE_URL", "http://localhost:8083")
	issuer := config.Env("AUTH_ISSUER", "http://localhost:8082")

	store := internal.NewMemStorage()
	authenticator := internal.NewHTTPAuthenticatorClient(authenticatorURL)

	handler := internal.Router(internal.Deps{
		Store:         store,
		Logger:        logger,
		Authenticator: authenticator,
		Issuer:        issuer,
	})

	addr := config.Addr(8082)
	if err := httpx.Run(context.Background(), logger, addr, handler); err != nil {
		logger.Error("server_exited_with_error", "err", err)
		os.Exit(1)
	}
}
