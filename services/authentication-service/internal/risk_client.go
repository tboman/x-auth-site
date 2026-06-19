package internal

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"

	"github.com/xentranet/x-auth/pkg/httpx"
	"github.com/xentranet/x-auth/pkg/tenantx"
	"github.com/xentranet/x-auth/pkg/tlsx"
)

// RiskAssessment is the slim view of risk-service's POST /v1/evaluations result
// the flow engine consumes. Field names mirror what policies reference via the
// `risk` env (see policyEnv): risk.tier, risk.score, risk.flags, risk.device, …
type RiskAssessment struct {
	Tier             string
	Score            float64
	Flags            []string
	Device           float64
	Behavior         float64
	Network          float64
	User             float64
	ImpossibleTravel bool
}

// RiskEvalInput is what the risk-evaluation stage forwards to risk-service.
type RiskEvalInput struct {
	TenantID    string
	UserID      string
	SessionID   string
	Action      string // e.g. "authorize"
	Resource    string // e.g. the client_id being authorized
	Sensitivity string // low | medium | high
	DeviceFP    string
	IP          string
	Country     string
	UserAgent   string
}

// RiskEvaluator is the surface of risk-service the flow engine depends on.
// Defining it as an interface keeps cmd/main.go thin and lets the stage be
// tested with a mock that returns a canned assessment.
type RiskEvaluator interface {
	Evaluate(ctx context.Context, in RiskEvalInput) (RiskAssessment, error)
}

// HTTPRiskClient calls risk-service POST /v1/evaluations. The endpoint is guarded
// by risk-service's V1_INTERNAL_ONLY gate, so requests carry the shared
// X-Internal-Auth header (set from INTERNAL_AUTH_SECRET, a no-op when unset).
type HTTPRiskClient struct {
	HTTP    *http.Client
	BaseURL string // e.g. https://risk-service-….run.app
	Logger  *slog.Logger
}

// NewHTTPRiskClient builds a risk client. baseURL is risk-service's root
// (RiskBaseURL of RISK_EVENTS_URL); empty baseURL yields a nil evaluator so the
// stage degrades to fail-open (no risk inputs) rather than erroring.
func NewHTTPRiskClient(logger *slog.Logger, baseURL string) (*HTTPRiskClient, error) {
	transport, err := tlsx.Transport(logger)
	if err != nil {
		return nil, err
	}
	return &HTTPRiskClient{
		HTTP:    &http.Client{Timeout: defaultClientTimeout, Transport: transport},
		BaseURL: strings.TrimRight(baseURL, "/"),
		Logger:  logger,
	}, nil
}

// riskEvalWire mirrors risk-service's EvaluateRequest body.
type riskEvalWire struct {
	UserID              string          `json:"user_id"`
	SessionID           string          `json:"session_id,omitempty"`
	Action              string          `json:"action"`
	Resource            string          `json:"resource,omitempty"`
	ResourceSensitivity string          `json:"resource_sensitivity"`
	Context             riskEvalCtxWire `json:"context"`
}

type riskEvalCtxWire struct {
	DeviceFingerprint string `json:"device_fingerprint,omitempty"`
	IPAddress         string `json:"ip_address,omitempty"`
	Country           string `json:"country,omitempty"`
	UserAgent         string `json:"user_agent,omitempty"`
}

// riskEvalRespWire mirrors the fields of risk-service's RiskEvaluation we use.
type riskEvalRespWire struct {
	Tier    string   `json:"tier"`
	Score   float64  `json:"score"`
	Flags   []string `json:"flags"`
	Signals struct {
		Device struct {
			Score float64 `json:"score"`
		} `json:"device"`
		Behavior struct {
			Score float64 `json:"score"`
		} `json:"behavior"`
		Network struct {
			Score float64 `json:"score"`
		} `json:"network"`
		User struct {
			Score float64 `json:"score"`
		} `json:"user"`
	} `json:"signals"`
}

func (c *HTTPRiskClient) Evaluate(ctx context.Context, in RiskEvalInput) (RiskAssessment, error) {
	sensitivity := in.Sensitivity
	if !ValidRiskLevel(sensitivity) { // risk-service rejects anything else
		sensitivity = RiskMedium
	}
	body := riskEvalWire{
		UserID:              in.UserID,
		SessionID:           in.SessionID,
		Action:              in.Action,
		Resource:            in.Resource,
		ResourceSensitivity: sensitivity,
		Context: riskEvalCtxWire{
			DeviceFingerprint: in.DeviceFP,
			IPAddress:         in.IP,
			Country:           in.Country,
			UserAgent:         in.UserAgent,
		},
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return RiskAssessment{}, &DownstreamError{Service: "risk-service", Err: err}
	}

	url := c.BaseURL + "/v1/evaluations"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return RiskAssessment{}, &DownstreamError{Service: "risk-service", Err: err}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if in.TenantID != "" {
		req.Header.Set(tenantx.Header, in.TenantID)
	}
	httpx.SetInternalAuth(req)

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return RiskAssessment{}, &DownstreamError{Service: "risk-service", Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(resp.Body)
		return RiskAssessment{}, &DownstreamError{Service: "risk-service", Status: resp.StatusCode, Body: string(b)}
	}

	var wire riskEvalRespWire
	if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
		return RiskAssessment{}, &DownstreamError{Service: "risk-service", Err: err}
	}
	return RiskAssessment{
		Tier:             wire.Tier,
		Score:            wire.Score,
		Flags:            wire.Flags,
		Device:           wire.Signals.Device.Score,
		Behavior:         wire.Signals.Behavior.Score,
		Network:          wire.Signals.Network.Score,
		User:             wire.Signals.User.Score,
		ImpossibleTravel: containsFlag(wire.Flags, "impossible_travel"),
	}, nil
}

func containsFlag(flags []string, want string) bool {
	for _, f := range flags {
		if f == want {
			return true
		}
	}
	return false
}
