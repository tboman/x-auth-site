package internal

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

// tokenCacheKey maps a consumer-page token to its verification id so replicas
// resolve /v/{token} without a DB round-trip. The store remains the source of
// truth; the cache is a best-effort accelerator.
const tokenCachePrefix = "id:vrf:token:"

// VerificationCache is an optional Redis accelerator for token→id lookups. A nil
// cache is a no-op; every method tolerates a nil receiver.
type VerificationCache struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewVerificationCache wraps a redis client. A nil client yields a nil cache.
func NewVerificationCache(rdb *redis.Client, ttl time.Duration) *VerificationCache {
	if rdb == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &VerificationCache{rdb: rdb, ttl: ttl}
}

func (c *VerificationCache) Put(ctx context.Context, token, id string) {
	if c == nil {
		return
	}
	_ = c.rdb.Set(ctx, tokenCachePrefix+token, id, c.ttl).Err()
}

func (c *VerificationCache) Get(ctx context.Context, token string) (string, bool) {
	if c == nil {
		return "", false
	}
	id, err := c.rdb.Get(ctx, tokenCachePrefix+token).Result()
	if err != nil {
		return "", false
	}
	return id, true
}

// isNoRows reports whether err is pgx's no-rows sentinel.
func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
