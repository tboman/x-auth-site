# Phase 2: Postgres

This doc is the shared contract every X-Auth service follows when it graduates from
the phase-1 in-memory store to Postgres. `transaction-service` is the reference
implementation; mirror its structure when migrating the remaining services.

## Shared pieces

- **`pkg/pgxdb`** — one-shot `Open(ctx, cfg, logger)` that parses the DSN, opens a
  `pgxpool.Pool`, pings once to fail fast, and logs a single `db_connect` event.
  Also ships `CloseOnContext` so graceful shutdown drops the pool cleanly.
- **Driver: `github.com/jackc/pgx/v5`** (no ORM). Queries live alongside each
  service's domain code.
- **Env vars**:
  - `PG_DSN` — repo-wide DSN fallback (useful for docker-compose).
  - `PG_DSN_<SERVICE>` — per-service override (`<SERVICE>` uppercased, `-` -> `_`).
    Example: `PG_DSN_TRANSACTION_SERVICE`.
  - `PG_MAX_CONNS` — pool ceiling (default `10`).

## Per-service convention

Each service owns its own schema under `services/<svc>/migrations/`, using
`golang-migrate`'s filename convention:

```
services/<svc>/migrations/
  000001_init.up.sql
  000001_init.down.sql
  000002_<topic>.up.sql
  000002_<topic>.down.sql
```

Why `golang-migrate`'s naming? It's the de-facto tool in the Go ecosystem, the CLI
is a single binary (no Go dependency), and the naming is tool-agnostic — any SQL
runner can iterate the files in order.

### Applying migrations (local dev)

Install once:

```bash
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
```

Apply:

```bash
migrate -path services/transaction-service/migrations \
        -database "$PG_DSN" up
```

Or plain psql if you don't want the extra dep:

```bash
psql "$PG_DSN" -f services/transaction-service/migrations/000001_init.up.sql
```

### Storage interface pattern

Every service keeps its phase-1 `Storage` interface (for example
`transaction-service/internal/storage.go`). Phase 2 adds a sibling
`pgstorage.go` that satisfies the same interface, and the `cmd/main.go` picks
between them by resolving the DSN:

```go
pool, err := pgxdb.Open(ctx, pgxdb.Config{ServiceName: "transaction-service"}, logger)
switch {
case err == nil:
    defer pool.Close()
    store = internal.NewPGStorage(pool)
case errors.Is(err, pgxdb.ErrMissingDSN):
    logger.Warn("db_fallback_memory", "reason", "PG_DSN unset")
    store = internal.NewMemStorage()
default:
    logger.Error("db_connect_failed", "err", err); os.Exit(1)
}
```

The in-memory fallback is deliberate: developer laptops, unit tests, and
short-lived CI runs all keep working without requiring a Postgres dependency.
Production (Cloud Run) always sets `PG_DSN`.

### Test pattern

- Unit tests against `MemStorage` continue to cover handler logic.
- PG-backed tests live in `<svc>/internal/pgstorage_test.go` and skip when the
  per-service DSN env var (e.g. `TXN_PG_DSN`) is unset. That way `go test ./...`
  stays green everywhere; integration tests run when a DB is provisioned.

## DDL notes

ARCHITECTURE.md §6.2 is the source of truth for table shapes. Phase-2 migrations
stay aligned with the doc with one narrow deviation: **string IDs stay TEXT**, not
UUID. The services mint prefixed ids (`txn_<uuid>`, `rev_<uuid>`, …) and treat
tenant / user / session ids as opaque strings. Moving to UUID columns is a
phase-2.1 cleanup that also requires the ID-minting side to change.

## Local dev — quick-start Postgres

```bash
docker run --rm -d --name xauth-pg \
  -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=postgres \
  -e POSTGRES_DB=txn_db -p 5432:5432 postgres:16

export PG_DSN="postgres://postgres:postgres@localhost:5432/txn_db?sslmode=disable"

# Apply migrations
migrate -path services/transaction-service/migrations -database "$PG_DSN" up

# Run the service
make run-transaction
```

Stop and wipe: `docker rm -f xauth-pg`.
