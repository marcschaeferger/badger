package badger

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// newSchemeTestBadger starts a Pangolin stub that records the verify-session
// body and answers exchange-session with a cookie (triggering a redirect to
// the original request URL). Only 10.0.0.0/8 is trusted.
func newSchemeTestBadger(t *testing.T) (http.Handler, *VerifyBody) {
	t.Helper()
	got := &VerifyBody{}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/badger/exchange-session":
			w.Write([]byte(`{"data":{"valid":true,"cookie":"p_session=x"}}`))
		case "/badger/verify-session":
			if err := json.NewDecoder(r.Body).Decode(got); err != nil {
				t.Errorf("decode verify body: %v", err)
			}
			w.Write([]byte(`{"data":{"valid":true}}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(api.Close)

	cfg := CreateConfig()
	cfg.APIBaseUrl = api.URL
	cfg.UserSessionCookieName = "p_session"
	cfg.ResourceSessionRequestParam = "p_session_request"
	cfg.TrustIP = []string{"10.0.0.0/8"}
	cfg.DisableDefaultCFIPs = true

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h, err := New(context.Background(), next, cfg, "badger")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h, got
}

func TestVerifySessionSendsRequestScheme(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		tls        bool
		headers    map[string]string
		wantScheme string
	}{
		{"tls connection", "203.0.113.5:1234", true, nil, "https"},
		{"plain http", "203.0.113.5:1234", false, nil, "http"},
		{"trusted proxy X-Forwarded-Proto", "10.0.0.1:1234", false, map[string]string{"X-Forwarded-Proto": "https"}, "https"},
		{"trusted proxy CF-Visitor", "10.0.0.1:1234", false, map[string]string{"CF-Visitor": `{"scheme":"https"}`}, "https"},
		{"untrusted X-Forwarded-Proto ignored", "203.0.113.5:1234", false, map[string]string{"X-Forwarded-Proto": "https"}, "http"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, got := newSchemeTestBadger(t)
			req := httptest.NewRequest(http.MethodGet, "/x", nil)
			req.Host = "app.example"
			req.RemoteAddr = tt.remoteAddr
			if !tt.tls {
				req.TLS = nil
			} else {
				req.TLS = &tls.ConnectionState{}
			}
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)

			scheme := ""
			if got.RequestScheme != nil {
				scheme = *got.RequestScheme
			}
			if scheme != tt.wantScheme {
				t.Errorf("scheme sent to Pangolin = %q, want %q", scheme, tt.wantScheme)
			}
			wantURL := tt.wantScheme + "://app.example/x"
			if got.OriginalRequestURL != wantURL {
				t.Errorf("originalRequestURL = %q, want %q", got.OriginalRequestURL, wantURL)
			}
		})
	}
}

func TestExchangeSessionRedirectUsesForwardedScheme(t *testing.T) {
	tests := []struct {
		name       string
		remoteAddr string
		headers    map[string]string
		wantLoc    string
	}{
		{"trusted proxy CF-Visitor https", "10.0.0.1:1234", map[string]string{"CF-Visitor": `{"scheme":"https"}`}, "https://app.example/x"},
		{"untrusted X-Forwarded-Proto https", "203.0.113.5:1234", map[string]string{"X-Forwarded-Proto": "https"}, "http://app.example/x"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, _ := newSchemeTestBadger(t)
			req := httptest.NewRequest(http.MethodGet, "/x?p_session_request=tok", nil)
			req.Host = "app.example"
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			if rec.Code != http.StatusFound {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
			}
			if loc := rec.Header().Get("Location"); loc != tt.wantLoc {
				t.Errorf("redirect Location = %q, want %q", loc, tt.wantLoc)
			}
		})
	}
}
