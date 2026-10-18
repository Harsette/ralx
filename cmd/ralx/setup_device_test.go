package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDevicePollDeniedExpiredAndCanceled(t *testing.T) {
	for _, reason := range []string{"access_denied", "expired_token", "invalid_grant"} {
		t.Run(reason, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(400)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
			}))
			defer server.Close()
			if _, err := setupDevicePoll(context.Background(), server.URL, setupDeviceResponse{DeviceCode: "synthetic", Interval: 0, ExpiresIn: 5}); err == nil {
				t.Fatal("terminal error ignored")
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := setupDevicePoll(ctx, "http://127.0.0.1:1", setupDeviceResponse{Interval: 5, ExpiresIn: 600}); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestDevicePollPendingSlowDownAndGrant(t *testing.T) {
	calls := 0
	var last time.Time
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.URL.Path != "/device/token" || r.Method != "POST" {
			t.Error("wrong endpoint")
		}
		var b map[string]string
		_ = json.NewDecoder(r.Body).Decode(&b)
		if b["device_code"] != "synthetic-device" {
			t.Error("device secret omitted")
		}
		if calls == 1 {
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
			return
		}
		if calls == 2 {
			last = time.Now()
			w.WriteHeader(400)
			_, _ = w.Write([]byte(`{"error":"slow_down","interval":5}`))
			return
		}
		if time.Since(last) < 5*time.Second {
			t.Error("CLI ignored slow_down")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"machine_grant": "mg_" + strings.Repeat("a", 64)})
	}))
	defer server.Close()
	grant, err := setupDevicePoll(context.Background(), server.URL, setupDeviceResponse{DeviceCode: "synthetic-device", Interval: 0, ExpiresIn: 10})
	if err != nil || grant != "mg_"+strings.Repeat("a", 64) {
		t.Fatal("grant failed", err)
	}
	if calls != 3 {
		t.Fatal("wrong poll count", calls)
	}
}

func TestDeviceApprovalNeverFollowsForeignVerificationURI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(setupDeviceResponse{DeviceCode: "dc_" + strings.Repeat("a", 64), UserCode: "BCDF-GHJK", VerificationURI: "https://evil.invalid/device", VerificationComplete: "https://evil.invalid/device?user_code=BCDF-GHJK", Interval: 5, ExpiresIn: 600})
	}))
	defer server.Close()
	if _, err := setupDeviceAuthorize(context.Background(), setupState{URL: server.URL}, []string{"codex"}, true); err == nil {
		t.Fatal("foreign verification origin accepted")
	}
}

func TestDeviceSecretPostNeverFollowsRedirect(t *testing.T) {
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true }))
	defer target.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer redirect.Close()
	_, _, _ = setupDevicePost(context.Background(), redirect.URL, "/device/token", map[string]string{"device_code": "synthetic-secret"})
	if reached {
		t.Fatal("device secret followed redirect")
	}
}

func TestSetupCloudOriginRejectsPathsAndCredentials(t *testing.T) {
	for _, value := range []string{"https://example.invalid/device", "https://alice:secret@example.invalid", "https://example.invalid?q=1", "https://example.invalid/#x", "http://example.invalid"} {
		if _, err := setupCloudOrigin(value); err == nil {
			t.Fatalf("unsafe origin accepted: %s", value)
		}
	}
	if got, err := setupCloudOrigin("https://example.invalid/"); err != nil || got != "https://example.invalid" {
		t.Fatal(got, err)
	}
}
