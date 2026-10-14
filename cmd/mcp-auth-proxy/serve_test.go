package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

var listeningPattern = regexp.MustCompile(`listening on [^\s:]+:(\d+)`)

type serveProcess struct {
	t      *testing.T
	stdout syncBuffer
	stderr syncBuffer
	cancel context.CancelFunc
	exited chan struct{}
	code   int
}

func startServe(t *testing.T, env map[string]string, args ...string) *serveProcess {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &serveProcess{t: t, cancel: cancel, exited: make(chan struct{})}
	go func() {
		s.code = run(ctx, args, &s.stdout, &s.stderr, envFunc(env))
		close(s.exited)
	}()
	t.Cleanup(func() {
		cancel()
		<-s.exited
	})
	return s
}

func (s *serveProcess) port() int {
	s.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		if match := listeningPattern.FindStringSubmatch(s.stderr.String()); match != nil {
			port, _ := strconv.Atoi(match[1])
			return port
		}
		select {
		case <-s.exited:
			s.t.Fatalf("serve exited with %d before listening\nstdout: %s\nstderr: %s", s.code, s.stdout.String(), s.stderr.String())
		case <-deadline:
			s.t.Fatalf("serve did not start listening\nstderr: %s", s.stderr.String())
		case <-time.After(10 * time.Millisecond):
		}
	}
}

func (s *serveProcess) stop() int {
	s.t.Helper()
	s.cancel()
	select {
	case <-s.exited:
	case <-time.After(10 * time.Second):
		s.t.Fatalf("serve did not shut down\nstderr: %s", s.stderr.String())
	}
	return s.code
}

type healthResponse struct {
	Strategies map[string]struct {
		AllowedHosts []string `json:"allowedHosts"`
		Auth         struct {
			HasCredentials bool `json:"hasCredentials"`
		} `json:"auth"`
	} `json:"strategies"`
}

func getHealth(t *testing.T, port int) healthResponse {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/_health", port))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("health status %d", resp.StatusCode)
	}
	var health healthResponse
	if err := json.NewDecoder(resp.Body).Decode(&health); err != nil {
		t.Fatal(err)
	}
	return health
}

func TestServeStartupAndShutdown(t *testing.T) {
	tests := []struct {
		name   string
		listen map[string]any
		env    map[string]string
		args   func(config string) []string
		want   []string
		unwant []string
	}{
		{
			name:   "serve with -p 0",
			listen: map[string]any{"port": 0},
			args:   func(c string) []string { return []string{"serve", "-c", c, "-p", "0"} },
			want:   []string{"listening on 127.0.0.1:"},
		},
		{
			name:   "port taken from the config",
			listen: map[string]any{"host": "127.0.0.1", "port": 0},
			args:   func(c string) []string { return []string{"serve", "-c", c} },
			want:   []string{"listening on 127.0.0.1:"},
		},
		{
			name:   "-p overrides the configured port",
			listen: map[string]any{"port": 1},
			args:   func(c string) []string { return []string{"serve", "--config", c, "--port=0"} },
			want:   []string{"listening on 127.0.0.1:"},
			unwant: []string{"listening on 127.0.0.1:1\n"},
		},
		{
			name:   "--host overrides the configured host",
			listen: map[string]any{"host": "0.0.0.0", "port": 0},
			args:   func(c string) []string { return []string{"serve", "-c", c, "--host", "127.0.0.1"} },
			want:   []string{"listening on 127.0.0.1:"},
			unwant: []string{"0.0.0.0", "non-loopback"},
		},
		{
			name:   "serve is the default command and the path comes from MCP_AUTH_PROXY_CONFIG",
			listen: map[string]any{"port": 0},
			env:    map[string]string{},
			args:   func(string) []string { return nil },
			want:   []string{"listening on 127.0.0.1:"},
		},
		{
			name:   "flags before the subcommand",
			listen: map[string]any{"port": 0},
			args:   func(c string) []string { return []string{"-c", c, "-p", "0", "serve"} },
			want:   []string{"listening on 127.0.0.1:"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			config := f.writeConfigWith(nil, tt.listen)
			env := tt.env
			if env != nil {
				env[configEnv] = config
			}

			s := startServe(t, env, tt.args(config)...)
			port := s.port()
			health := getHealth(t, port)

			if got := s.stop(); got != 0 {
				t.Fatalf("exit code %d, want 0\nstderr: %s", got, s.stderr.String())
			}
			output := s.stderr.String()
			contains(t, "stderr", output, tt.want)
			contains(t, "stderr", output, []string{
				fmt.Sprintf("listening on 127.0.0.1:%d", port),
				"strategy up: allowedHosts *.example.com, https://api.foo.dev",
				"strategy multi: allowedHosts tenant.example.org, http://localhost:3000",
				"strategy long: allowedHosts *.example.com, https://api.foo.dev",
				"shutting down",
			})
			excludes(t, "stderr", output, tt.unwant)
			if tokenPattern.MatchString(output) || s.stdout.String() != "" {
				t.Errorf("unexpected output\nstdout: %q\nstderr: %s", s.stdout.String(), output)
			}
			if long, multi, up := strings.Index(output, "strategy long:"), strings.Index(output, "strategy multi:"), strings.Index(output, "strategy up:"); long > multi || multi > up {
				t.Errorf("strategy lines are not sorted:\n%s", output)
			}
			if len(health.Strategies) != 3 {
				t.Errorf("health lists %d strategies, want 3", len(health.Strategies))
			}
			if got := strings.Join(health.Strategies["multi"].AllowedHosts, ","); got != "tenant.example.org,http://localhost:3000" {
				t.Errorf("multi allowedHosts = %q", got)
			}
			if got := strings.Join(health.Strategies["up"].AllowedHosts, ","); got != "*.example.com,https://api.foo.dev" {
				t.Errorf("up allowedHosts = %q", got)
			}
		})
	}
}

func TestServeRejectsAForeignHostHeader(t *testing.T) {
	f := newFixture(t)
	s := startServe(t, nil, "serve", "-c", f.writeConfigWith(nil, map[string]any{"port": 0}), "-p", "0")
	port := s.port()

	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/_health", port), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "evil.example"
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status %d, want 403", resp.StatusCode)
	}
}

func TestServeProxiesWithInjectedCredentialsAndHonorsDebug(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		logLevel  string
		wantDebug bool
	}{
		{"info level logs no request lines", nil, "info", false},
		{"--debug logs request lines", []string{"--debug"}, "info", true},
		{"logLevel debug in the config logs request lines", nil, "debug", true},
		{"--debug together with logLevel debug", []string{"--debug"}, "debug", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var mu sync.Mutex
			var seenAuth string
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				seenAuth = r.Header.Get("Proxy-Authorization")
				mu.Unlock()
				io.WriteString(w, "pong")
			}))
			t.Cleanup(upstream.Close)
			f := newFixture(t)
			config := f.writeRawConfig("config.yaml", map[string]any{
				"logLevel":     tt.logLevel,
				"listen":       map[string]any{"port": 0},
				"allowedHosts": []string{upstream.URL},
				"strategies": map[string]any{
					"up": map[string]any{"command": "bash ./gen.sh", "output": "token", "cwd": f.dir, "env": f.genEnv("token", 3600)},
				},
			})

			s := startServe(t, nil, append([]string{"serve", "-c", config, "-p", "0"}, tt.args...)...)
			port := s.port()

			req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/", port), nil)
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("X-Proxy-Strategy", "up")
			req.Header.Set("X-Proxy-Target", upstream.URL+"/ping")
			req.Header.Set("Proxy-Authorization", "Bearer {{token}}")
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != http.StatusOK || string(body) != "pong" {
				t.Fatalf("proxied response %d %q", resp.StatusCode, body)
			}
			mu.Lock()
			gotAuth := seenAuth
			mu.Unlock()
			if !regexp.MustCompile(`^Bearer \S+$`).MatchString(gotAuth) || strings.Contains(gotAuth, "{{") {
				t.Errorf("upstream saw Proxy-Authorization %q", gotAuth)
			}
			if got := s.stop(); got != 0 {
				t.Fatalf("exit code %d", got)
			}
			output := s.stderr.String()
			if hasDebug := strings.Contains(output, "DEBUG"); hasDebug != tt.wantDebug {
				t.Errorf("DEBUG lines present = %v, want %v\n%s", hasDebug, tt.wantDebug, output)
			}
			if strings.Contains(output, strings.TrimPrefix(gotAuth, "Bearer ")) {
				t.Errorf("log output leaks the credential:\n%s", output)
			}
		})
	}
}

func TestServeStartupFailureExitsOne(t *testing.T) {
	f := newFixture(t)
	taken, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { taken.Close() })
	port := strconv.Itoa(taken.Addr().(*net.TCPAddr).Port)

	got := runCLI(t, nil, "serve", "-c", f.writeConfig(), "--host", "127.0.0.1", "-p", port)

	if got.code != 1 {
		t.Fatalf("exit code %d, want 1\nstderr: %s", got.code, got.stderr)
	}
	contains(t, "stderr", got.stderr, []string{"error:"})
	excludes(t, "output", got.stdout+got.stderr, []string{"listening on", "config error"})
}
