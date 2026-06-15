package smsx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStubVerifier(t *testing.T) {
	v := Stub{}
	if err := v.Start(context.Background(), "+15551112222"); err != nil {
		t.Fatalf("stub start: %v", err)
	}
	if ok, err := v.Check(context.Background(), "+15551112222", StubCode); err != nil || !ok {
		t.Fatalf("stub check valid: ok=%v err=%v", ok, err)
	}
	if ok, _ := v.Check(context.Background(), "+15551112222", "000000"); ok {
		t.Fatal("stub check should reject a wrong code")
	}
}

func TestNewFallsBackToStub(t *testing.T) {
	if _, ok := New(Config{}, nil).(Stub); !ok {
		t.Fatal("unconfigured New must return a Stub")
	}
	full := Config{AccountSID: "AC1", AuthSecret: "s", VerifyServiceSID: "VA1"}
	if _, ok := New(full, nil).(*TwilioVerify); !ok {
		t.Fatal("configured New must return TwilioVerify")
	}
}

// TestTwilioVerifyRoundTrip points the client at a fake Verify endpoint and
// checks the start/check requests + status mapping.
func TestTwilioVerifyRoundTrip(t *testing.T) {
	var startHit, checkHit bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, _ := r.BasicAuth()
		if user != "SKkey" || pass != "secret" {
			t.Errorf("basic auth = %q:%q, want SKkey:secret", user, pass)
		}
		_ = r.ParseForm()
		switch {
		case strings.HasSuffix(r.URL.Path, "/Verifications"):
			startHit = true
			if r.PostForm.Get("To") != "+15551112222" || r.PostForm.Get("Channel") != "sms" {
				t.Errorf("start form = %v", r.PostForm)
			}
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		case strings.HasSuffix(r.URL.Path, "/VerificationCheck"):
			checkHit = true
			status := "approved"
			if r.PostForm.Get("Code") != "654321" {
				status = "pending"
			}
			_, _ = w.Write([]byte(`{"status":"` + status + `"}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	}))
	defer srv.Close()

	tv := &TwilioVerify{
		cfg: Config{APIKeySID: "SKkey", AuthSecret: "secret", VerifyServiceSID: "VA1"},
		hc:  srv.Client(),
	}
	// Redirect the base URL at the test server by overriding via the service path.
	tv.cfg.VerifyServiceSID = "VA1"
	tv.base = srv.URL + "/v2/Services/"

	if err := tv.Start(context.Background(), "+15551112222"); err != nil {
		t.Fatalf("start: %v", err)
	}
	if ok, err := tv.Check(context.Background(), "+15551112222", "654321"); err != nil || !ok {
		t.Fatalf("check valid: ok=%v err=%v", ok, err)
	}
	if ok, err := tv.Check(context.Background(), "+15551112222", "000000"); err != nil || ok {
		t.Fatalf("check wrong: ok=%v err=%v", ok, err)
	}
	if !startHit || !checkHit {
		t.Fatalf("endpoints not hit: start=%v check=%v", startHit, checkHit)
	}
}
