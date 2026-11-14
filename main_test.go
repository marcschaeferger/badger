package badger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// newBlockingPangolin starts a stub Pangolin API that never answers until the
// test finishes, simulating a hung upstream.
func newBlockingPangolin(t *testing.T) *httptest.Server {
	t.Helper()
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Cleanups run LIFO: unblock the handler before closing the server.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })
	return srv
}

func newTestBadger(t *testing.T, apiBaseURL string, next http.Handler) http.Handler {
	t.Helper()
	cfg := CreateConfig()
	cfg.APIBaseUrl = apiBaseURL
	cfg.UserSessionCookieName = "p_session"
	cfg.ResourceSessionRequestParam = "p_session_request"
	cfg.DisableDefaultCFIPs = true
	h, err := New(context.Background(), next, cfg, "badger-test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func TestServeHTTPReturnsWhenRequestCancelledDuringPangolinCall(t *testing.T) {
	cases := []struct {
		name   string
		target string
	}{
		{name: "verify-session", target: "http://app.example.com/"},
		{name: "exchange-session", target: "http://app.example.com/?p_session_request=token"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pangolin := newBlockingPangolin(t)

			nextCalled := make(chan struct{}, 1)
			next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				nextCalled <- struct{}{}
			})
			h := newTestBadger(t, pangolin.URL, next)

			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			req := httptest.NewRequest(http.MethodGet, tc.target, nil).WithContext(ctx)
			rec := httptest.NewRecorder()

			done := make(chan struct{})
			go func() {
				h.ServeHTTP(rec, req)
				close(done)
			}()

			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("ServeHTTP still blocked on Pangolin 2s after the request context was cancelled")
			}

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("status = %d, want %d (fail closed)", rec.Code, http.StatusInternalServerError)
			}
			select {
			case <-nextCalled:
				t.Fatal("next handler was called although Pangolin never answered")
			default:
			}
		})
	}
}

func TestNewConfiguresPangolinClientTimeout(t *testing.T) {
	h := newTestBadger(t, "http://pangolin.invalid", http.NotFoundHandler())
	b, ok := h.(*Badger)
	if !ok {
		t.Fatalf("New returned %T, want *Badger", h)
	}
	if b.httpClient == nil {
		t.Fatal("httpClient is nil; Pangolin calls would use http.DefaultClient without a timeout")
	}
	if b.httpClient.Timeout <= 0 {
		t.Fatalf("httpClient.Timeout = %v, want a positive timeout", b.httpClient.Timeout)
	}
}
