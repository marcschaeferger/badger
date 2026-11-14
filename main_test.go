package badger

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func newTestBadger(t *testing.T, api *httptest.Server) http.Handler {
	t.Helper()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		rw.WriteHeader(http.StatusOK)
	})
	cfg := CreateConfig()
	cfg.APIBaseUrl = api.URL
	cfg.UserSessionCookieName = "p_session"
	cfg.ResourceSessionRequestParam = "p_session_request"
	cfg.AccessTokenQueryParam = "p_token"
	cfg.DisableDefaultCFIPs = true
	h, err := New(context.Background(), next, cfg, "badger")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return h
}

func TestExchangeSessionRedirectPreservesEscapedPath(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/badger/exchange-session" {
			t.Errorf("unexpected API call %s", req.URL.Path)
			http.Error(rw, "unexpected", http.StatusInternalServerError)
			return
		}
		var resp ExchangeSessionResponse
		resp.Data.Valid = true
		cookie := "p_session=abc; Path=/"
		resp.Data.Cookie = &cookie
		_ = json.NewEncoder(rw).Encode(resp)
	}))
	defer api.Close()

	h := newTestBadger(t, api)
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/files/a%3Fb%23c/100%25/x%2Fy?p_session_request=tok", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	want := "http://app.example.com/files/a%3Fb%23c/100%25/x%2Fy"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}

func TestAccessTokenRedirectPreservesEscapedPath(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/badger/verify-session" {
			t.Errorf("unexpected API call %s", req.URL.Path)
			http.Error(rw, "unexpected", http.StatusInternalServerError)
			return
		}
		var resp VerifyResponse
		resp.Data.Valid = true
		rw.Header().Add("Set-Cookie", "p_session=abc; Path=/")
		_ = json.NewEncoder(rw).Encode(resp)
	}))
	defer api.Close()

	h := newTestBadger(t, api)
	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/files/a%3Fb%23c/100%25/x%2Fy?keep=1&p_token=tok", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusFound)
	}
	want := "http://app.example.com/files/a%3Fb%23c/100%25/x%2Fy?keep=1"
	if got := rec.Header().Get("Location"); got != want {
		t.Errorf("Location = %q, want %q", got, want)
	}
}
