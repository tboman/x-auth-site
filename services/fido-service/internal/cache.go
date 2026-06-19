package internal

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/redis/go-redis/v9"
)

// blobCacheKey holds the verified raw blob shared across replicas.
const blobCacheKey = "fido:mds:blob:current"

// BlobCache is an optional Redis cache of the raw verified blob, so replicas
// share one upstream fetch and cold starts come up warm. nil cache is a no-op.
type BlobCache struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewBlobCache wraps a redis client. A nil client yields a nil cache; all
// methods tolerate a nil receiver.
func NewBlobCache(rdb *redis.Client, ttl time.Duration) *BlobCache {
	if rdb == nil {
		return nil
	}
	if ttl <= 0 {
		ttl = 48 * time.Hour
	}
	return &BlobCache{rdb: rdb, ttl: ttl}
}

func (c *BlobCache) Get(ctx context.Context) ([]byte, bool, error) {
	if c == nil {
		return nil, false, nil
	}
	b, err := c.rdb.Get(ctx, blobCacheKey).Bytes()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, false, nil
		}
		return nil, false, err
	}
	return b, true, nil
}

func (c *BlobCache) Set(ctx context.Context, raw []byte) error {
	if c == nil {
		return nil
	}
	return c.rdb.Set(ctx, blobCacheKey, raw, c.ttl).Err()
}

// isNoRows reports whether err is pgx's no-rows sentinel.
func isNoRows(err error) bool {
	return errors.Is(err, pgx.ErrNoRows)
}
