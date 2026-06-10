package ratex

import (
	"context"
	"log/slog"
	"time"

	"github.com/redis/go-redis/v9"
)

// allowScript implements the ARCHITECTURE.md §6.3 counter pattern
// (rate:{key} → counter, TTL = window) atomically: increment, stamp the TTL
// on first hit, and when over the limit report the time until the window
// resets. Returns {allowed(0|1), retry_after_ms}.
var allowScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
if count > tonumber(ARGV[2]) then
  local ttl = redis.call('PTTL', KEYS[1])
  if ttl < 0 then
    redis.call('PEXPIRE', KEYS[1], ARGV[1])
    ttl = tonumber(ARGV[1])
  end
  return {0, ttl}
end
return {1, 0}
`)

// RedisLimiter enforces "at most limit events per window per key" with shared
// fixed-window counters in Redis (key pattern `rate:{key}`, §6.3), making the
// limit hold across replicas. Fixed windows admit up to 2x the limit across a
// window boundary in the worst case — accepted for §10.5 abuse prevention in
// exchange for O(1) state per key.
//
// Decisions FAIL OPEN: when Redis is unreachable the limiter allows the
// request and logs `rate_limit_redis_error` — §10.5 is an abuse-prevention
// layer, and dropping all traffic because the cache died is the worse failure.
type RedisLimiter struct {
	client  redis.Scripter
	limit   int
	window  time.Duration
	prefix  string
	logger  *slog.Logger
	timeout time.Duration
}

// NewRedis builds a RedisLimiter. prefix namespaces the counters (e.g.
// "rate:txn" → keys "rate:txn:{key}") so services sharing one Redis don't
// collide. limit <= 0 disables the limiter (Allow always succeeds).
func NewRedis(client redis.Scripter, limit int, window time.Duration, prefix string, logger *slog.Logger) *RedisLimiter {
	return &RedisLimiter{
		client:  client,
		limit:   limit,
		window:  window,
		prefix:  prefix,
		logger:  logger,
		timeout: 2 * time.Second,
	}
}

// Allow implements Allower against the shared counters.
func (l *RedisLimiter) Allow(key string) (bool, time.Duration) {
	if l == nil || l.limit <= 0 {
		return true, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), l.timeout)
	defer cancel()

	res, err := allowScript.Run(ctx, l.client,
		[]string{l.prefix + ":" + key},
		l.window.Milliseconds(), l.limit,
	).Int64Slice()
	if err != nil || len(res) != 2 {
		l.logger.Error("rate_limit_redis_error", "err", err, "prefix", l.prefix)
		return true, 0 // fail open
	}
	if res[0] == 1 {
		return true, 0
	}
	return false, time.Duration(res[1]) * time.Millisecond
}
