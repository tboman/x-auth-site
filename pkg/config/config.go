// Package config provides small helpers for reading environment variables.
package config

import (
	"os"
	"strconv"
)

// Addr returns the listen address, respecting Cloud Run's PORT env var.
// Falls back to defaultPort if PORT is unset.
func Addr(defaultPort int) string {
	if p := os.Getenv("PORT"); p != "" {
		return ":" + p
	}
	return ":" + strconv.Itoa(defaultPort)
}

// Env returns the value of key, or fallback if unset or empty.
func Env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// Require returns the value of key or panics if it is unset.
func Require(key string) string {
	v := os.Getenv(key)
	if v == "" {
		panic("required env var not set: " + key)
	}
	return v
}
