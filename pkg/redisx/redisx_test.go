package redisx

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"

	"github.com/xentranet/x-auth/pkg/logx"
)

func clearEnv(t *testing.T) {
	t.Helper()
	for _, v := range []string{EnvURL, EnvAddr, EnvPassword, EnvDB} {
		t.Setenv(v, "")
	}
}

func TestOpenMissingAddr(t *testing.T) {
	clearEnv(t)
	_, err := Open(context.Background(), Config{ServiceName: "test"}, logx.New("redisx-test"))
	if !errors.Is(err, ErrMissingAddr) {
		t.Fatalf("want ErrMissingAddr, got %v", err)
	}
}

func TestOpenViaAddrEnv(t *testing.T) {
	clearEnv(t)
	mr := miniredis.RunT(t)
	t.Setenv(EnvAddr, mr.Addr())

	client, err := Open(context.Background(), Config{ServiceName: "test"}, logx.New("redisx-test"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer client.Close()
	if err := client.Set(context.Background(), "k", "v", time.Minute).Err(); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := client.Get(context.Background(), "k").Result()
	if err != nil || got != "v" {
		t.Fatalf("get: %q %v", got, err)
	}
}

func TestOpenViaURLEnv(t *testing.T) {
	clearEnv(t)
	mr := miniredis.RunT(t)
	t.Setenv(EnvURL, "redis://"+mr.Addr()+"/2")

	client, err := Open(context.Background(), Config{ServiceName: "test"}, logx.New("redisx-test"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer client.Close()
	if client.Options().DB != 2 {
		t.Fatalf("URL db not honored: %d", client.Options().DB)
	}
}

func TestOpenPingFailsFast(t *testing.T) {
	clearEnv(t)
	// A port that is almost certainly closed.
	t.Setenv(EnvAddr, "127.0.0.1:1")
	start := time.Now()
	_, err := Open(context.Background(), Config{PingTimeout: 2 * time.Second}, logx.New("redisx-test"))
	if err == nil {
		t.Fatal("want connection error")
	}
	if errors.Is(err, ErrMissingAddr) {
		t.Fatal("must not be ErrMissingAddr — addr was set")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("ping did not fail fast: %v", elapsed)
	}
}

func TestOpenBadURL(t *testing.T) {
	clearEnv(t)
	t.Setenv(EnvURL, "not a url ://")
	if _, err := Open(context.Background(), Config{}, logx.New("redisx-test")); err == nil {
		t.Fatal("garbage URL must error")
	}
}

func TestOpenBadDB(t *testing.T) {
	clearEnv(t)
	mr := miniredis.RunT(t)
	t.Setenv(EnvAddr, mr.Addr())
	t.Setenv(EnvDB, "not-a-number")
	if _, err := Open(context.Background(), Config{}, logx.New("redisx-test")); err == nil {
		t.Fatal("non-integer REDIS_DB must error")
	}
}
