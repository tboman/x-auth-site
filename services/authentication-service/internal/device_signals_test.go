package internal

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestDeviceSignalStorageMem covers append + tenant-scoped newest-first listing.
func TestDeviceSignalStorageMem(t *testing.T) {
	s := NewMemStorage()
	now := time.Now().UTC()
	for i, st := range []string{DeviceStageSocial, DeviceStageOTP, DeviceStagePasskey} {
		if err := s.RecordDeviceSignal(DeviceSignal{
			ID: fmt.Sprintf("dvs_%d", i), TenantID: "ten_a", UserID: "u",
			Stage: st, Fingerprint: fmt.Sprintf("fp%d", i), CreatedAt: now.Add(time.Duration(i) * time.Second),
		}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}
	_ = s.RecordDeviceSignal(DeviceSignal{ID: "dvs_b", TenantID: "ten_b", Stage: DeviceStageSocial, Fingerprint: "fpb", CreatedAt: now})

	got, _ := s.ListDeviceSignals("ten_a", 0)
	if len(got) != 3 || got[0].Fingerprint != "fp2" || got[2].Fingerprint != "fp0" {
		t.Fatalf("ten_a signals wrong/order: %+v", got)
	}
	if capped, _ := s.ListDeviceSignals("ten_a", 1); len(capped) != 1 || capped[0].Fingerprint != "fp2" {
		t.Fatalf("cap not applied: %+v", capped)
	}
}

// TestDeviceSignalCaptureSocial: a device_fp on the social leg is recorded at
// the social-login validation (stage=social).
func TestDeviceSignalCaptureSocial(t *testing.T) {
	r, store := newAdminRouter(t) // stub social
	if err := store.PutClient(OIDCClient{
		ClientID: "cli", TenantID: "ten_acme", RedirectURIs: []string{"https://app.acme.test/cb"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	q := url.Values{"tenant_id": {"ten_acme"}, "redirect_uri": {"https://app.acme.test/cb"}, "state": {"s"}, "device_fp": {"fp-social-1"}}
	aw := httptest.NewRecorder()
	r.ServeHTTP(aw, httptest.NewRequest(http.MethodGet, "/v1/social/google/authorize?"+q.Encode(), nil))
	if aw.Code != http.StatusFound {
		t.Fatalf("authorize: want 302, got %d (%s)", aw.Code, aw.Body.String())
	}
	cw := httptest.NewRecorder()
	r.ServeHTTP(cw, httptest.NewRequest(http.MethodGet, aw.Header().Get("Location"), nil))
	if cw.Code != http.StatusFound {
		t.Fatalf("callback: want 302, got %d (%s)", cw.Code, cw.Body.String())
	}
	sigs, _ := store.ListDeviceSignals("ten_acme", 0)
	if len(sigs) != 1 || sigs[0].Fingerprint != "fp-social-1" || sigs[0].Stage != DeviceStageSocial {
		t.Fatalf("social device signal not recorded: %+v", sigs)
	}
	if sigs[0].UserID == "" {
		t.Fatal("social device signal should carry the resolved user_id")
	}
}

// TestDeviceSignalCapturePhone: a device_fp on the phone OTP verify is recorded
// (stage=otp).
func TestDeviceSignalCapturePhone(t *testing.T) {
	r, store := phoneTestRouter(t)
	flow := submitPhone(t, r, "+15551112222")
	w := postForm(t, r, "/login/phone/verify", url.Values{"flow": {flow}, "code": {stubOTPCode}, "device_fp": {"fp-phone-1"}})
	if w.Code != http.StatusOK { // new number → link offer
		t.Fatalf("verify: want 200 link offer, got %d", w.Code)
	}
	sigs, _ := store.ListDeviceSignals("ten_acme", 0)
	if len(sigs) != 1 || sigs[0].Fingerprint != "fp-phone-1" || sigs[0].Stage != DeviceStageOTP {
		t.Fatalf("phone device signal not recorded: %+v", sigs)
	}
}

// TestDeviceSignalCaptureStepUp: a device_fp on the /authorize step-up verify is
// recorded (stage=otp for sms).
func TestDeviceSignalCaptureStepUp(t *testing.T) {
	r, store := newOTPRouter(t, &mockAuthenticator{
		ListFn: func(_ context.Context, _, _ string) ([]Authenticator, error) {
			return []Authenticator{{ID: "atr", Method: "sms", Status: "active"}}, nil
		},
	})
	flowID, _ := startStepUpAuthorize(t, r, ACRSMSOTP)
	w := postForm(t, r, "/authorize/verify", url.Values{"flow": {flowID}, "code": {"123456"}, "device_fp": {"fp-stepup-1"}})
	if w.Code != http.StatusFound {
		t.Fatalf("verify: want 302, got %d (%s)", w.Code, w.Body.String())
	}
	sigs, _ := store.ListDeviceSignals("ten_acme", 0)
	if len(sigs) != 1 || sigs[0].Fingerprint != "fp-stepup-1" || sigs[0].Stage != DeviceStageOTP {
		t.Fatalf("step-up device signal not recorded: %+v", sigs)
	}
}

// TestDeviceFPScriptOnHostedPages: the FingerprintJS capture script + the
// data-device-fp hooks are present on the login chooser.
func TestDeviceFPScriptOnHostedPages(t *testing.T) {
	r, store := newAdminRouter(t)
	if err := store.PutClient(OIDCClient{
		ClientID: "cli", TenantID: "ten_acme", RedirectURIs: []string{"https://app.acme.test/cb"}, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("seed client: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/login?tenant_id=ten_acme&redirect_uri="+url.QueryEscape("https://app.acme.test/cb")+"&state=s", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	body := w.Body.String()
	for _, want := range []string{"openfpcdn.io/fingerprintjs", "data-device-fp"} {
		if !strings.Contains(body, want) {
			t.Errorf("/login missing %q", want)
		}
	}
}

// TestAdminTenantDeviceSignalsView: the master-admin tenant page renders the
// device-signals panel with the recorded observation.
func TestAdminTenantDeviceSignalsView(t *testing.T) {
	r, store := newAdminRouter(t, "tomasboman@gmail.com")
	now := time.Now().UTC()
	mustUser(t, store, "usr_a", "ten_acme", "a@acme.test", now)
	_ = store.RecordDeviceSignal(DeviceSignal{
		ID: "dvs_1", TenantID: "ten_acme", UserID: "usr_a", Stage: DeviceStageSocial,
		Fingerprint: "fp-view-1", IPAddress: "203.0.113.9", CreatedAt: now,
	})
	cookie := adminCookie(t, r, store, "tomasboman@gmail.com")

	det := httptest.NewRequest(http.MethodGet, "/admin/tenants/ten_acme", nil)
	det.AddCookie(&http.Cookie{Name: adminSessionCookie, Value: cookie})
	dw := httptest.NewRecorder()
	r.ServeHTTP(dw, det)
	body := dw.Body.String()
	for _, want := range []string{"Device signals", "fp-view-1", "203.0.113.9", ">social<", "a@acme.test"} {
		if !strings.Contains(body, want) {
			t.Errorf("tenant detail missing %q", want)
		}
	}
}
