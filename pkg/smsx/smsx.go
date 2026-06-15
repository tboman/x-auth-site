// Package smsx delivers and checks phone one-time codes behind a small Verifier
// interface. The real implementation is Twilio Verify (Twilio generates, texts,
// and validates the code — we never store it); when Twilio isn't configured the
// package falls back to a Stub that "sends" nothing and accepts StubCode, so
// local dev and tests run without a provider.
package smsx

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// Verifier starts an OTP (texts a code to phone) and checks a submitted code.
type Verifier interface {
	// Start sends a fresh one-time code to phone (E.164). An error means the code
	// was not sent.
	Start(ctx context.Context, phone string) error
	// Check reports whether code is the valid current code for phone. A false with
	// nil error is a wrong/expired code; a non-nil error is a transport/provider
	// failure the caller should surface as "try again".
	Check(ctx context.Context, phone, code string) (bool, error)
}

// StubCode is the fixed code the Stub verifier accepts when Twilio is unconfigured.
const StubCode = "123456"

// Config holds Twilio Verify credentials. AuthSecret pairs with either the
// account auth token (AccountSID as the basic-auth user) or an API key
// (APIKeySID as the user) — whichever is set.
type Config struct {
	AccountSID       string
	APIKeySID        string // optional; when set it is the basic-auth user (preferred — scoped/revocable)
	AuthSecret       string // auth token, or the API key secret
	VerifyServiceSID string // the Verify Service SID (VA...)
}

// ConfigFromEnv reads the standard TWILIO_* environment variables. Values are
// trimmed of surrounding whitespace: a secret stored with a trailing newline is
// a common cause of a Twilio 401 (error 20003), and the SIDs never contain
// whitespace, so trimming is always safe.
func ConfigFromEnv() Config {
	return Config{
		AccountSID:       strings.TrimSpace(os.Getenv("TWILIO_ACCOUNT_SID")),
		APIKeySID:        strings.TrimSpace(os.Getenv("TWILIO_API_KEY_SID")),
		AuthSecret:       strings.TrimSpace(os.Getenv("TWILIO_AUTH_SECRET")),
		VerifyServiceSID: strings.TrimSpace(os.Getenv("TWILIO_VERIFY_SERVICE_SID")),
	}
}

// Configured reports whether enough is set to talk to Twilio Verify.
func (c Config) Configured() bool {
	return c.AccountSID != "" && c.AuthSecret != "" && c.VerifyServiceSID != ""
}

// New returns a TwilioVerify when fully configured, otherwise a Stub (logged so
// the fallback is obvious in the boot logs).
func New(cfg Config, logger *slog.Logger) Verifier {
	if cfg.Configured() {
		if logger != nil {
			logger.Info("sms_verifier", "provider", "twilio_verify", "verify_service_sid", cfg.VerifyServiceSID)
		}
		return &TwilioVerify{cfg: cfg, log: logger, hc: &http.Client{Timeout: 10 * time.Second}, base: twilioVerifyBase}
	}
	if logger != nil {
		logger.Warn("sms_verifier", "provider", "stub",
			"reason", "TWILIO_ACCOUNT_SID/TWILIO_AUTH_SECRET/TWILIO_VERIFY_SERVICE_SID unset — OTP delivery is a stub that accepts "+StubCode)
	}
	return Stub{log: logger}
}

// Stub is the no-provider fallback: it logs the "send" and accepts StubCode.
type Stub struct{ log *slog.Logger }

func (s Stub) Start(_ context.Context, phone string) error {
	if s.log != nil {
		s.log.Info("sms_otp_sent_stub", "phone", phone, "code", StubCode)
	}
	return nil
}

func (s Stub) Check(_ context.Context, _, code string) (bool, error) {
	return code == StubCode, nil
}

// TwilioVerify calls the Twilio Verify v2 API over HTTPS (no SDK — the API is
// simple form-POST + JSON, which keeps go.mod lean).
type TwilioVerify struct {
	cfg  Config
	log  *slog.Logger
	hc   *http.Client
	base string // Verify API base; overridable in tests. Empty → twilioVerifyBase.
}

const twilioVerifyBase = "https://verify.twilio.com/v2/Services/"

// Start creates a verification, which texts a fresh code to phone.
func (t *TwilioVerify) Start(ctx context.Context, phone string) error {
	status, httpCode, err := t.post(ctx, "/Verifications", url.Values{"To": {phone}, "Channel": {"sms"}})
	if err != nil {
		return err
	}
	if httpCode < 200 || httpCode >= 300 {
		return fmt.Errorf("twilio verify start: http %d", httpCode)
	}
	_ = status
	return nil
}

// Check validates a submitted code. A Twilio 404 means the verification no
// longer exists (expired, already approved, or max attempts) — reported as a
// non-error "not approved" so the caller shows "incorrect code", not a 5xx.
func (t *TwilioVerify) Check(ctx context.Context, phone, code string) (bool, error) {
	status, httpCode, err := t.post(ctx, "/VerificationCheck", url.Values{"To": {phone}, "Code": {code}})
	if err != nil {
		return false, err
	}
	if httpCode == http.StatusNotFound {
		return false, nil
	}
	if httpCode < 200 || httpCode >= 300 {
		return false, fmt.Errorf("twilio verify check: http %d", httpCode)
	}
	return status == "approved", nil
}

// post sends a form body to the Verify service path and returns the decoded
// "status" field plus the HTTP status code. err is transport-level only.
func (t *TwilioVerify) post(ctx context.Context, path string, form url.Values) (status string, httpCode int, err error) {
	base := t.base
	if base == "" {
		base = twilioVerifyBase
	}
	endpoint := base + t.cfg.VerifyServiceSID + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", 0, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	user := t.cfg.AccountSID
	if t.cfg.APIKeySID != "" {
		user = t.cfg.APIKeySID
	}
	req.SetBasicAuth(user, t.cfg.AuthSecret)

	resp, err := t.hc.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("twilio verify %s: %w", path, err)
	}
	defer resp.Body.Close()

	var body struct {
		Status  string `json:"status"`
		Code    int    `json:"code"`
		Message string `json:"message"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&body)
	if resp.StatusCode >= 400 && t.log != nil && resp.StatusCode != http.StatusNotFound {
		t.log.Error("twilio_verify_error", "path", path, "http", resp.StatusCode, "code", body.Code, "message", body.Message)
	}
	return body.Status, resp.StatusCode, nil
}
