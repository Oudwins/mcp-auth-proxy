package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/config"
)

const initializeLine = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"test","version":"0"}}}`

type upstreamRequest struct {
	method string
	path   string
	header http.Header
	body   string
}

type stdioUpstream struct {
	server *httptest.Server
	mu     sync.Mutex
	seen   []upstreamRequest
}

func startStdioUpstream(t *testing.T) *stdioUpstream {
	t.Helper()
	u := &stdioUpstream{}
	u.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.seen = append(u.seen, upstreamRequest{method: r.Method, path: r.URL.Path, header: r.Header.Clone(), body: string(body)})
		u.mu.Unlock()

		switch r.Method {
		case http.MethodPost:
			var msg struct {
				ID     json.RawMessage `json:"id"`
				Method string          `json:"method"`
			}
			_ = json.Unmarshal(body, &msg)
			if msg.Method != "initialize" {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			w.Header().Set("Mcp-Session-Id", "sess-1")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-03-26","capabilities":{},"serverInfo":{"name":"mock","version":"1"}}}`, msg.ID)
		case http.MethodGet:
			w.WriteHeader(http.StatusMethodNotAllowed)
		default:
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(u.server.Close)
	return u
}

func (u *stdioUpstream) requests() []upstreamRequest {
	u.mu.Lock()
	defer u.mu.Unlock()
	return append([]upstreamRequest(nil), u.seen...)
}

func (u *stdioUpstream) first(method string) (upstreamRequest, bool) {
	for _, r := range u.requests() {
		if r.method == method {
			return r, true
		}
	}
	return upstreamRequest{}, false
}

func (u *stdioUpstream) url() string { return u.server.URL + "/mcp" }

func (f *fixture) writeStdioConfig(allowedHost string) string {
	return f.writeRawConfig("stdio-config.yaml", map[string]any{
		"allowedHosts": []string{allowedHost},
		"strategies": map[string]any{
			"tok": map[string]any{"command": []string{"sh", "-c", "echo tok123"}},
		},
	})
}

func runStdioCLI(t *testing.T, stdin io.Reader, env map[string]string, args ...string) result {
	t.Helper()
	var stdout, stderr syncBuffer
	code := run(context.Background(), args, stdin, &stdout, &stderr, envFunc(env))
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

func jsonLines(t *testing.T, stdout string) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, line := range strings.Split(strings.TrimSuffix(stdout, "\n"), "\n") {
		if line == "" {
			continue
		}
		var msg map[string]any
		if err := json.Unmarshal([]byte(line), &msg); err != nil {
			t.Fatalf("stdout line is not JSON: %q", line)
		}
		out = append(out, msg)
	}
	return out
}

func TestStdioBridgesToTheUpstreamWithInjectedHeaders(t *testing.T) {
	for _, prefix := range [][]string{nil, {"stdio"}} {
		name := "default"
		if prefix != nil {
			name = "explicit stdio"
		}
		t.Run(name, func(t *testing.T) {
			upstream := startStdioUpstream(t)
			f := newFixture(t)
			config := f.writeStdioConfig(upstream.server.URL)
			args := append(append([]string{}, prefix...),
				"-s", "tok", "-t", upstream.url(),
				"-H", "Authorization: Bearer {{token}}",
				"-H", "X-Tenant: ${env:TENANT}",
				"-c", config)
			stdin := strings.NewReader(initializeLine + "\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n")

			got := runStdioCLI(t, stdin, map[string]string{"TENANT": "acme"}, args...)

			if got.code != 0 {
				t.Fatalf("exit code %d\nstdout: %s\nstderr: %s", got.code, got.stdout, got.stderr)
			}
			lines := jsonLines(t, got.stdout)
			if len(lines) != 1 {
				t.Fatalf("stdout has %d JSON lines, want 1\n%s", len(lines), got.stdout)
			}
			if id, _ := lines[0]["id"].(float64); id != 1 {
				t.Errorf("response id = %v, want 1", lines[0]["id"])
			}
			payload, _ := lines[0]["result"].(map[string]any)
			if info, _ := payload["serverInfo"].(map[string]any); info["name"] != "mock" {
				t.Errorf("response is not the upstream initialize result: %s", got.stdout)
			}

			post, ok := upstream.first(http.MethodPost)
			if !ok {
				t.Fatal("the upstream saw no POST")
			}
			if auth := post.header.Get("Authorization"); auth != "Bearer tok123" {
				t.Errorf("upstream saw Authorization %q, want %q", auth, "Bearer tok123")
			}
			if tenant := post.header.Get("X-Tenant"); tenant != "acme" {
				t.Errorf("upstream saw X-Tenant %q, want acme", tenant)
			}
			if post.path != "/mcp" {
				t.Errorf("upstream saw path %q, want /mcp", post.path)
			}
			for _, r := range upstream.requests() {
				for headerName := range r.header {
					if strings.HasPrefix(strings.ToLower(headerName), "x-proxy-") {
						t.Errorf("control header %s reached the upstream", headerName)
					}
				}
			}
			excludes(t, "stderr", got.stderr, []string{"tok123"})
			if strings.Contains(got.stdout, "tok123") {
				t.Errorf("stdout leaks the token: %s", got.stdout)
			}
		})
	}
}

func TestStdioStreamsUntilInputCloses(t *testing.T) {
	upstream := startStdioUpstream(t)
	f := newFixture(t)
	pr, pw := io.Pipe()
	var stdout, stderr syncBuffer
	done := make(chan int, 1)
	go func() {
		done <- run(context.Background(),
			[]string{"-s", "tok", "-t", upstream.url(), "-H", "Authorization: Bearer {{token}}", "-c", f.writeStdioConfig(upstream.server.URL)},
			pr, &stdout, &stderr, envFunc(nil))
	}()

	if _, err := io.WriteString(pw, initializeLine+"\n"); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(10 * time.Second)
	for !strings.Contains(stdout.String(), "\n") {
		select {
		case code := <-done:
			t.Fatalf("exited with %d before answering\nstderr: %s", code, stderr.String())
		case <-deadline:
			t.Fatalf("no response on stdout\nstderr: %s", stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
	pw.Close()

	select {
	case code := <-done:
		if code != 0 {
			t.Fatalf("exit code %d\nstderr: %s", code, stderr.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("run did not return after stdin closed")
	}
	if got := len(jsonLines(t, stdout.String())); got != 1 {
		t.Errorf("stdout has %d JSON lines, want 1", got)
	}
	del, ok := upstream.first(http.MethodDelete)
	if !ok || del.header.Get("Mcp-Session-Id") != "sess-1" {
		t.Errorf("expected a session DELETE on shutdown, got %+v", upstream.requests())
	}
}

func TestStdioOpensNoPort(t *testing.T) {
	upstream := startStdioUpstream(t)
	f := newFixture(t)
	config := f.writeRawConfig("busy.yaml", map[string]any{
		"listen":       map[string]any{"host": "203.0.113.1", "port": 1},
		"allowedHosts": []string{upstream.server.URL},
		"strategies":   map[string]any{"tok": map[string]any{"command": []string{"sh", "-c", "echo tok123"}}},
	})

	got := runStdioCLI(t, strings.NewReader(initializeLine+"\n"), nil,
		"-s", "tok", "-t", upstream.url(), "-H", "Authorization: Bearer {{token}}", "-c", config)

	if got.code != 0 {
		t.Fatalf("exit code %d\nstderr: %s", got.code, got.stderr)
	}
	excludes(t, "stderr", got.stderr, []string{"listening on"})
}

func TestStdioUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"no arguments", nil, "--strategy"},
		{"missing strategy", []string{"-t", "https://x.test/mcp"}, "--strategy"},
		{"missing target", []string{"-s", "tok"}, "--target"},
		{"explicit stdio missing both", []string{"stdio"}, "--strategy"},
		{"--port is rejected", []string{"-s", "tok", "-t", "https://x.test/mcp", "--port", "0"}, "--port"},
		{"-p is rejected", []string{"-s", "tok", "-t", "https://x.test/mcp", "-p", "0"}, "--port"},
		{"--host is rejected", []string{"stdio", "-s", "tok", "-t", "https://x.test/mcp", "--host", "127.0.0.1"}, "--host"},
		{"header without a colon", []string{"-s", "tok", "-t", "https://x.test/mcp", "-H", "Authorization"}, `invalid header "Authorization"`},
		{"header with an empty name", []string{"-s", "tok", "-t", "https://x.test/mcp", "-H", ": value"}, "empty header name"},
		{"header with an invalid name", []string{"-s", "tok", "-t", "https://x.test/mcp", "-H", "Bad Name: v"}, "bad header name"},
		{"reserved header", []string{"-s", "tok", "-t", "https://x.test/mcp", "-H", "X-Proxy-Target: https://evil.test"}, "reserved"},
		{"reserved header is case-insensitive", []string{"-s", "tok", "-t", "https://x.test/mcp", "-H", "x-PROXY-strategy: other"}, "reserved"},
		{"extra positional", []string{"stdio", "extra", "-s", "tok", "-t", "https://x.test/mcp"}, `unexpected argument "extra" for stdio`},
		{"-s with http", []string{"http", "-s", "tok"}, "--strategy is only valid in stdio mode"},
		{"-t with http", []string{"http", "-t", "https://x.test/mcp"}, "--target is only valid in stdio mode"},
		{"-H with http", []string{"http", "-H", "A: b"}, "--header is only valid in stdio mode"},
		{"-s with check", []string{"check", "-s", "tok"}, "--strategy is only valid in stdio mode"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runCLI(t, nil, tt.args...)
			if got.code != 2 {
				t.Fatalf("exit code %d, want 2\nstderr: %s", got.code, got.stderr)
			}
			contains(t, "stderr", got.stderr, []string{tt.want, "Usage:"})
			if got.stdout != "" {
				t.Errorf("stdout should be empty, got %q", got.stdout)
			}
		})
	}
}

func TestServeIsAnUnknownCommand(t *testing.T) {
	f := newFixture(t)

	got := runCLI(t, nil, "serve", "-c", f.writeConfig())

	if got.code != 2 {
		t.Fatalf("exit code %d, want 2", got.code)
	}
	contains(t, "stderr", got.stderr, []string{`unknown command "serve"`})
}

func TestStdioConfigErrors(t *testing.T) {
	tests := []struct {
		name  string
		extra []string
		env   map[string]string
		want  []string
	}{
		{
			name:  "unknown strategy lists the available ones",
			extra: []string{"-s", "nope", "-t", "https://x.test/mcp"},
			want:  []string{"config error: unknown strategy(ies): nope", "available: tok"},
		},
		{
			name:  "unset environment variable is named",
			extra: []string{"-s", "tok", "-t", "https://x.test/mcp", "-H", "X-Key: ${env:MISSING_KEY}"},
			want:  []string{"config error:", "MISSING_KEY", `"X-Key"`},
		},
		{
			name:  "empty environment variable is a config error",
			extra: []string{"-s", "tok", "-t", "https://x.test/mcp", "-H", "X-Key: ${env:EMPTY_KEY}"},
			env:   map[string]string{"EMPTY_KEY": ""},
			want:  []string{"config error:", "EMPTY_KEY"},
		},
		{
			name:  "every missing variable is named",
			extra: []string{"-s", "tok", "-t", "https://x.test/mcp", "-H", "X-Key: ${env:ONE}-${env:TWO}"},
			want:  []string{"ONE, TWO"},
		},
		{
			name:  "line breaks in an expanded value are rejected",
			extra: []string{"-s", "tok", "-t", "https://x.test/mcp", "-H", "X-Key: ${env:BAD}"},
			env:   map[string]string{"BAD": "a\r\nX-Evil: 1"},
			want:  []string{"config error:", "line break"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			args := append(append([]string{}, tt.extra...), "-c", f.writeStdioConfig("https://x.test"))

			got := runStdioCLI(t, strings.NewReader(initializeLine+"\n"), tt.env, args...)

			if got.code != 2 {
				t.Fatalf("exit code %d, want 2\nstderr: %s", got.code, got.stderr)
			}
			contains(t, "stderr", got.stderr, tt.want)
			if got.stdout != "" {
				t.Errorf("stdout should be empty, got %q", got.stdout)
			}
		})
	}
}

func TestParseArgsHeaders(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"short separate value", []string{"-H", "A: 1"}, []string{"A: 1"}},
		{"short attached value", []string{`-HA: 1`}, []string{"A: 1"}},
		{"long with equals", []string{"--header=A: 1"}, []string{"A: 1"}},
		{"long separate value", []string{"--header", "A: 1"}, []string{"A: 1"}},
		{"repeated and mixed", []string{"-H", "A: 1", "--header=B: 2", "-HC: 3"}, []string{"A: 1", "B: 2", "C: 3"}},
		{"value containing equals", []string{"--header=A: x=y"}, []string{"A: x=y"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseArgs(tt.args)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.headers, tt.want) {
				t.Errorf("headers = %q, want %q", got.headers, tt.want)
			}
		})
	}

	t.Run("missing value", func(t *testing.T) {
		if _, err := parseArgs([]string{"-H"}); err == nil || !strings.Contains(err.Error(), `option "-H" requires a value`) {
			t.Errorf("err = %v", err)
		}
	})

	t.Run("strategy and target forms", func(t *testing.T) {
		got, err := parseArgs([]string{"-s", "a", "--target=https://x.test/mcp"})
		if err != nil {
			t.Fatal(err)
		}
		if got.strategy == nil || *got.strategy != "a" || got.target == nil || *got.target != "https://x.test/mcp" {
			t.Errorf("parsed %+v", got)
		}
	})
}

func TestBuildHeaders(t *testing.T) {
	env := envFunc(map[string]string{"TENANT": "acme", "REGION": "eu"})

	t.Run("expands env references and keeps placeholders verbatim", func(t *testing.T) {
		lines, err := parseHeaderLines([]string{
			"Authorization:   Bearer {{token}}  ",
			"X-Scope: ${env:TENANT}/${env:REGION}",
			"x-multi: one",
			"X-Multi: two",
		})
		if err != nil {
			t.Fatal(err)
		}
		headers, err := buildHeaders(lines, env)
		if err != nil {
			t.Fatal(err)
		}
		if got := headers.Get("Authorization"); got != "Bearer {{token}}" {
			t.Errorf("Authorization = %q", got)
		}
		if got := headers.Get("X-Scope"); got != "acme/eu" {
			t.Errorf("X-Scope = %q", got)
		}
		if got := headers.Values("X-Multi"); !reflect.DeepEqual(got, []string{"one", "two"}) {
			t.Errorf("X-Multi = %q", got)
		}
	})

	t.Run("a missing variable is a config error", func(t *testing.T) {
		lines, _ := parseHeaderLines([]string{"X-A: ${env:NOPE}"})
		_, err := buildHeaders(lines, env)
		var configErr *config.ConfigError
		if !errors.As(err, &configErr) || !strings.Contains(configErr.Message, "NOPE") {
			t.Errorf("err = %v", err)
		}
	})
}
