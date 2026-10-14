package proxy

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/logger"
)

func startLocalStack(t *testing.T) (*Local, *mockUpstream) {
	t.Helper()
	mock := startMockUpstream(t, false, "")
	cfg := buildConfig(t, stackOptions{}, mock.origin())
	local, err := StartLocal(Options{Config: cfg, Log: logger.New(true, &syncBuffer{})})
	if err != nil {
		t.Fatalf("StartLocal failed: %v", err)
	}
	t.Cleanup(local.Close)
	return local, mock
}

func localRequest(t *testing.T, local *Local, target string, extra H) (*http.Response, []byte, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, local.URL+"ping", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Proxy-Strategy", "up")
	req.Header.Set("X-Proxy-Target", target)
	req.Header.Set("Proxy-Authorization", "Bearer {{token}}")
	for name, value := range extra {
		req.Header.Set(name, value)
	}
	resp, err := local.Client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return resp, body, err
}

func TestLocalInjectsCredential(t *testing.T) {
	t.Parallel()
	local, mock := startLocalStack(t)

	resp, body, err := localRequest(t, local, mock.URL, nil)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, body %s", resp.StatusCode, body)
	}
	if got := string(body); !strings.Contains(got, `"ok":true`) || !strings.Contains(got, `"body":"{}"`) {
		t.Fatalf("body = %s", got)
	}
	wantTokenSerial(t, mock.last(t), 1)
	for name := range mock.last(t).Header {
		if strings.HasPrefix(strings.ToLower(name), "x-proxy-") {
			t.Errorf("control header %s reached the upstream", name)
		}
	}
	if local.Providers["up"] == nil {
		t.Error("Providers is missing the up strategy")
	}
}

func TestLocalRejectsOrigin(t *testing.T) {
	t.Parallel()
	local, mock := startLocalStack(t)

	resp, body, err := localRequest(t, local, mock.URL, H{"Origin": "http://evil.example"})
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	reply{status: resp.StatusCode, header: resp.Header, body: body}.wantError(t, http.StatusForbidden, "forbidden_origin")
	if got := len(mock.requests()); got != 0 {
		t.Fatalf("upstream saw %d requests, want 0", got)
	}
}

func TestLocalCloseStopsServing(t *testing.T) {
	t.Parallel()
	local, mock := startLocalStack(t)

	if _, _, err := localRequest(t, local, mock.URL, nil); err != nil {
		t.Fatalf("request before close failed: %v", err)
	}

	done := make(chan struct{})
	go func() {
		local.Close()
		local.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return promptly")
	}

	if _, _, err := localRequest(t, local, mock.URL, nil); err == nil {
		t.Fatal("request after Close succeeded, want an error")
	}
}
