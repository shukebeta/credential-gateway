package gateway

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"credential-gateway/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

func startProxy(t *testing.T, upstream string, headers map[string]string) *httpProxy {
	t.Helper()
	p := &httpProxy{
		cfg: config.HTTPService{
			Name:     "test",
			Listen:   "127.0.0.1:0",
			Upstream: upstream,
			Headers:  headers,
		},
		log: testLogger(),
	}
	if err := p.Start(); err != nil {
		t.Fatalf("proxy start: %v", err)
	}
	t.Cleanup(func() { p.Stop(context.Background()) }) //nolint:errcheck
	return p
}

func TestHTTPProxy_InjectsConfiguredHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := startProxy(t, srv.URL, map[string]string{"Authorization": "Bearer sk-injected"})

	resp, err := http.Get(fmt.Sprintf("http://%s/v1/models", p.addr))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer sk-injected" {
		t.Errorf("upstream got Authorization %q, want %q", gotAuth, "Bearer sk-injected")
	}
}

func TestHTTPProxy_StripsClientCredentialHeader(t *testing.T) {
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	p := startProxy(t, srv.URL, map[string]string{"Authorization": "Bearer sk-real"})

	req, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s/v1/chat", p.addr), nil)
	req.Header.Set("Authorization", "Bearer hacked")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if gotAuth != "Bearer sk-real" {
		t.Errorf("upstream got Authorization %q, want configured %q", gotAuth, "Bearer sk-real")
	}
}

func TestHTTPProxy_StreamingResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		flusher, ok := w.(http.Flusher)
		if !ok {
			t.Error("upstream ResponseWriter does not implement http.Flusher")
			return
		}
		for i := range 3 {
			fmt.Fprintf(w, "data: chunk%d\n\n", i)
			flusher.Flush()
		}
	}))
	defer srv.Close()

	p := startProxy(t, srv.URL, map[string]string{"Authorization": "Bearer sk-stream"})

	resp, err := http.Get(fmt.Sprintf("http://%s/v1/stream", p.addr))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !strings.Contains(string(body), "data: chunk0") {
		t.Errorf("streaming body missing expected chunks, got: %q", string(body))
	}
	if resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", resp.Header.Get("Content-Type"))
	}
}

func TestHTTPProxy_UpstreamErrorReturns502(t *testing.T) {
	p := startProxy(t, "http://127.0.0.1:1", map[string]string{"Authorization": "Bearer sk-x"})

	resp, err := http.Get(fmt.Sprintf("http://%s/v1/models", p.addr))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("got status %d, want 502", resp.StatusCode)
	}
}
