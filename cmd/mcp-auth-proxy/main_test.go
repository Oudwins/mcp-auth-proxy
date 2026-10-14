package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const genScript = `#!/usr/bin/env bash
set -euo pipefail

: "${STATE_DIR:?STATE_DIR is required}"

if [ -e "$STATE_DIR/fail" ]; then
  echo "Reauthentication is needed: ADC credentials expired" >&2
  exit 1
fi

n=$(( $(cat "$STATE_DIR/count" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$STATE_DIR/count"

exp=$(( $(date +%s) + ${TOKEN_LIFETIME:-3600} ))
token="tok.${n}.${exp}"

case "${GEN_FORMAT:-json}" in
  token)
    echo "$token"
    ;;
  multi)
    printf '{"values":{"token":"%s","tenant":"acme corp"},"expiresAt":%s}\n' "$token" "$exp"
    ;;
  *)
    printf '{"values":{"token":"%s"},"expiresAt":%s}\n' "$token" "$exp"
    ;;
esac
`

const longToken = "abcdefghijklmnopqrstuvwxyz0123456789"

var tokenPattern = regexp.MustCompile(`tok\.\d+\.\d{10}`)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type result struct {
	code   int
	stdout string
	stderr string
}

func envFunc(env map[string]string) func(string) string {
	return func(key string) string { return env[key] }
}

func runCLI(t *testing.T, env map[string]string, args ...string) result {
	t.Helper()
	var stdout, stderr syncBuffer
	code := run(context.Background(), args, &stdout, &stderr, envFunc(env))
	return result{code: code, stdout: stdout.String(), stderr: stderr.String()}
}

type fixture struct {
	t   *testing.T
	dir string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gen.sh"), []byte(genScript), 0o755); err != nil {
		t.Fatal(err)
	}
	return &fixture{t: t, dir: dir}
}

func (f *fixture) genEnv(format string, lifetime int) map[string]any {
	return map[string]any{"STATE_DIR": f.dir, "TOKEN_LIFETIME": strconv.Itoa(lifetime), "GEN_FORMAT": format}
}

func (f *fixture) writeRawConfig(name string, config any) string {
	f.t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		f.t.Fatal(err)
	}
	return f.writeFile(name, string(data))
}

func (f *fixture) writeFile(name, content string) string {
	f.t.Helper()
	path := filepath.Join(f.dir, name)
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		f.t.Fatal(err)
	}
	return path
}

func (f *fixture) writeConfig() string {
	return f.writeConfigWith(nil, nil)
}

func (f *fixture) writeConfigWith(allowedHosts []string, listen map[string]any) string {
	f.t.Helper()
	if allowedHosts == nil {
		allowedHosts = []string{"*.example.com", "https://api.foo.dev"}
	}
	config := map[string]any{
		"allowedHosts": allowedHosts,
		"strategies": map[string]any{
			"up": map[string]any{
				"command": "bash ./gen.sh",
				"output":  "token",
				"ttl":     "1h",
				"cwd":     f.dir,
				"env":     f.genEnv("token", 3600),
			},
			"multi": map[string]any{
				"command":      []string{"bash", "./gen.sh"},
				"output":       "json",
				"cwd":          f.dir,
				"env":          f.genEnv("multi", 10800),
				"allowedHosts": []string{"tenant.example.org", "http://localhost:3000"},
			},
			"long": map[string]any{
				"command": []string{"echo", longToken},
				"ttl":     600,
			},
		},
	}
	if listen != nil {
		config["listen"] = listen
	}
	return f.writeRawConfig("config.yaml", config)
}

func (f *fixture) makeGeneratorFail() {
	f.writeFile("fail", "")
}

func contains(t *testing.T, label, text string, wants []string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(text, want) {
			t.Errorf("%s missing %q\n%s", label, want, text)
		}
	}
}

func excludes(t *testing.T, label, text string, unwanted []string) {
	t.Helper()
	for _, bad := range unwanted {
		if strings.Contains(text, bad) {
			t.Errorf("%s must not contain %q\n%s", label, bad, text)
		}
	}
}

func matches(t *testing.T, label, text string, patterns []string) {
	t.Helper()
	for _, pattern := range patterns {
		if !regexp.MustCompile(pattern).MatchString(text) {
			t.Errorf("%s does not match %s\n%s", label, pattern, text)
		}
	}
}

func TestHelpAndVersion(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want []string
	}{
		{"long help", []string{"--help"}, []string{"Usage:", "check [strategy...]", "config.yaml", "--debug", "MCP_AUTH_PROXY_CONFIG"}},
		{"short help", []string{"-h"}, []string{"Usage:"}},
		{"help after subcommand", []string{"check", "--help"}, []string{"Usage:"}},
		{"long version", []string{"--version"}, []string{version}},
		{"short version", []string{"-v"}, []string{version}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runCLI(t, nil, tt.args...)
			if got.code != 0 {
				t.Fatalf("exit code %d, stderr %q", got.code, got.stderr)
			}
			contains(t, "stdout", got.stdout, tt.want)
			if got.stderr != "" {
				t.Errorf("stderr should be empty, got %q", got.stderr)
			}
		})
	}

	t.Run("version prints only the version", func(t *testing.T) {
		got := runCLI(t, nil, "--version")
		if strings.TrimSpace(got.stdout) != version {
			t.Errorf("stdout = %q, want %q", got.stdout, version)
		}
	})
}

func TestUsageErrors(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"unknown command", []string{"bogus"}, `unknown command "bogus"`},
		{"unknown long flag", []string{"check", "--bogus"}, `unknown option "--bogus"`},
		{"unknown short flag", []string{"-x"}, `unknown option "-x"`},
		{"unknown flag in cluster", []string{"-dh"}, `unknown option "-d"`},
		{"missing value for long flag", []string{"--config"}, `option "--config" requires a value`},
		{"missing value for short flag", []string{"check", "-p"}, `option "-p" requires a value`},
		{"value for boolean flag", []string{"--debug=1"}, `option "--debug" does not take a value`},
		{"serve with positional", []string{"serve", "extra"}, `unexpected argument "extra" for serve`},
		{"command after double dash is still validated", []string{"--", "nope"}, `unknown command "nope"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runCLI(t, nil, tt.args...)
			if got.code != 2 {
				t.Fatalf("exit code %d, want 2", got.code)
			}
			contains(t, "stderr", got.stderr, []string{tt.want, "Usage:"})
			if got.stdout != "" {
				t.Errorf("stdout should be empty, got %q", got.stdout)
			}
		})
	}
}

func TestBadPort(t *testing.T) {
	f := newFixture(t)
	config := f.writeConfig()
	for _, command := range []string{"check", "serve"} {
		for _, port := range []string{"abc", "70000", "-1", "1.5", "", "65536"} {
			t.Run(command+" "+port, func(t *testing.T) {
				got := runCLI(t, nil, command, "-c", config, "--port="+port)
				if got.code != 2 {
					t.Fatalf("exit code %d, want 2", got.code)
				}
				contains(t, "stderr", got.stderr, []string{`config error: invalid --port "` + port + `"`})
				if strings.Contains(got.stdout+got.stderr, "listening on") {
					t.Error("must not start listening")
				}
			})
		}
	}

	t.Run("short form with separate value", func(t *testing.T) {
		got := runCLI(t, nil, "serve", "-c", config, "-p", "abc")
		if got.code != 2 || !strings.Contains(got.stderr, `invalid --port "abc"`) {
			t.Fatalf("code %d stderr %q", got.code, got.stderr)
		}
	})

	t.Run("boundary ports are accepted by check", func(t *testing.T) {
		for _, port := range []string{"0", "65535"} {
			got := runCLI(t, nil, "check", "long", "-c", config, "-p", port)
			if got.code != 0 {
				t.Errorf("port %s: exit code %d, stderr %q", port, got.code, got.stderr)
			}
		}
	})
}

func TestFlagPlacement(t *testing.T) {
	f := newFixture(t)
	config := f.writeConfig()
	tests := []struct {
		name string
		args []string
	}{
		{"flags after the strategy", []string{"check", "long", "-c", config}},
		{"flags between subcommand and strategy", []string{"check", "-c", config, "long"}},
		{"flags before the subcommand", []string{"-c", config, "check", "long"}},
		{"long flag with equals", []string{"--config=" + config, "check", "long"}},
		{"long flag with separate value", []string{"check", "long", "--config", config}},
		{"short flag with attached value", []string{"check", "long", "-c" + config}},
		{"strategy after double dash", []string{"-c", config, "check", "--", "long"}},
		{"debug flag", []string{"check", "long", "--debug", "-c", config}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := runCLI(t, nil, tt.args...)
			if got.code != 0 {
				t.Fatalf("exit code %d, stderr %q", got.code, got.stderr)
			}
			contains(t, "stdout", got.stdout, []string{"long: ok"})
			excludes(t, "stdout", got.stdout, []string{"up: ok", "multi: ok"})
		})
	}
}

func TestCheck(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		config       func(f *fixture) string
		failing      bool
		code         int
		stdout       []string
		stdoutRegexp []string
		notStdout    []string
		stderr       []string
	}{
		{
			name: "prints the masked value, expiry and allowed hosts",
			args: []string{"check", "up"},
			stdout: []string{
				"up: ok",
				"  allowedHosts: *.example.com, https://api.foo.dev",
			},
			stdoutRegexp: []string{
				`(?m)^  \{\{token\}\}: \(16 chars\)$`,
				`(?m)^  expires: \d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z \(in \d+m, from ttl\)$`,
			},
		},
		{
			name:      "shows the first six characters only for values of 24 characters or more",
			args:      []string{"check", "long"},
			stdout:    []string{"  {{token}}: abcdef... (36 chars)"},
			notStdout: []string{"abcdefghij"},
		},
		{
			name:   "prints one line per value and credits an explicit expiry from the output",
			args:   []string{"check", "multi"},
			stdout: []string{"multi: ok", "(in 3h, from output)"},
			stdoutRegexp: []string{
				`(?m)^  \{\{tenant\}\}: \(9 chars\)$`,
				`(?m)^  \{\{token\}\}: \(16 chars\)$`,
			},
			notStdout: []string{"acme corp"},
		},
		{
			name: "a strategy allowedHosts override replaces the global list",
			args: []string{"check"},
			stdout: []string{
				"  allowedHosts: tenant.example.org, http://localhost:3000",
				"  allowedHosts: *.example.com, https://api.foo.dev",
			},
		},
		{
			name:   "checks every strategy by default",
			args:   []string{"check"},
			stdout: []string{"up: ok", "multi: ok", "long: ok"},
		},
		{
			name:      "checks only the named strategies",
			args:      []string{"check", "long", "up"},
			stdout:    []string{"long: ok", "up: ok"},
			notStdout: []string{"multi: ok"},
		},
		{
			name:      "exits 1 and shows the generator error when it fails",
			args:      []string{"check", "up"},
			failing:   true,
			code:      1,
			stdout:    []string{"up: FAILED", "ADC credentials expired"},
			notStdout: []string{"up: ok"},
		},
		{
			name:    "keeps checking after a failure and still exits 1",
			args:    []string{"check"},
			failing: true,
			code:    1,
			stdout:  []string{"up: FAILED", "multi: FAILED", "long: ok"},
		},
		{
			name: "reports output that does not match the configured mode as a failure",
			args: []string{"check"},
			config: func(f *fixture) string {
				return f.writeRawConfig("config.yaml", map[string]any{
					"allowedHosts": []string{"api.example.com"},
					"strategies": map[string]any{
						"mismatch": map[string]any{"command": "bash ./gen.sh", "output": "token", "cwd": f.dir, "env": f.genEnv("multi", 3600)},
					},
				})
			},
			code:   1,
			stdout: []string{"mismatch: FAILED"},
		},
		{
			name:      "exits 2 for an unknown strategy without running any generator",
			args:      []string{"check", "up", "nope"},
			code:      2,
			stderr:    []string{"config error: unknown strategy(ies): nope", "available: long, multi, up"},
			notStdout: []string{"up: ok"},
		},
		{
			name:   "lists every unknown strategy",
			args:   []string{"check", "x", "up", "y"},
			code:   2,
			stderr: []string{"unknown strategy(ies): x, y"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newFixture(t)
			config := f.writeConfig()
			if tt.config != nil {
				config = tt.config(f)
			}
			if tt.failing {
				f.makeGeneratorFail()
			}

			got := runCLI(t, nil, append(tt.args, "-c", config)...)

			if got.code != tt.code {
				t.Fatalf("exit code %d, want %d\nstdout: %s\nstderr: %s", got.code, tt.code, got.stdout, got.stderr)
			}
			contains(t, "stdout", got.stdout, tt.stdout)
			matches(t, "stdout", got.stdout, tt.stdoutRegexp)
			excludes(t, "stdout", got.stdout, tt.notStdout)
			contains(t, "stderr", got.stderr, tt.stderr)
			for label, text := range map[string]string{"stdout": got.stdout, "stderr": got.stderr} {
				if tokenPattern.MatchString(text) {
					t.Errorf("%s leaks a generated token:\n%s", label, text)
				}
				excludes(t, label, text, []string{longToken, "acme corp"})
			}
		})
	}
}

func TestCheckRunsStrategiesInSortedOrder(t *testing.T) {
	f := newFixture(t)

	got := runCLI(t, nil, "check", "-c", f.writeConfig())

	long, multi, up := strings.Index(got.stdout, "long: ok"), strings.Index(got.stdout, "multi: ok"), strings.Index(got.stdout, "up: ok")
	if long < 0 || long > multi || multi > up {
		t.Errorf("strategies out of order:\n%s", got.stdout)
	}
}

func TestCheckFailureDetailsGoToStdoutAndNeverLeakCredentials(t *testing.T) {
	f := newFixture(t)
	config := f.writeRawConfig("config.yaml", map[string]any{
		"allowedHosts": []string{"api.example.com"},
		"strategies": map[string]any{
			"leaky": map[string]any{"command": []string{"sh", "-c", "echo 'rejected: Bearer s3cr3t-credential-value' >&2; exit 1"}},
		},
	})

	got := runCLI(t, nil, "check", "-c", config)

	if got.code != 1 {
		t.Fatalf("exit code %d", got.code)
	}
	contains(t, "stdout", got.stdout, []string{"leaky: FAILED"})
	excludes(t, "stdout", got.stdout, []string{"s3cr3t-credential-value"})
	excludes(t, "stderr", got.stderr, []string{"s3cr3t-credential-value"})
}

func TestConfigErrors(t *testing.T) {
	const unsetVar = "MCP_AUTH_PROXY_TEST_UNSET"
	tests := []struct {
		name   string
		args   []string
		config func(f *fixture) string
		want   []string
	}{
		{
			name:   "missing file",
			config: func(f *fixture) string { return filepath.Join(f.dir, "missing.yaml") },
			want:   []string{"config error: cannot read config"},
		},
		{
			name: "malformed YAML",
			config: func(f *fixture) string {
				return f.writeFile("config.yaml", "strategies: [unclosed\n  a: {")
			},
			want: []string{"config error:", "not valid YAML"},
		},
		{
			name: "invalid config names each problem",
			config: func(f *fixture) string {
				return f.writeRawConfig("config.yaml", map[string]any{
					"allowedHosts": []string{"ftp://bad"},
					"strategies":   map[string]any{"a": map[string]any{"command": "g", "ttl": "soon"}},
				})
			},
			want: []string{"config error: invalid config:", "allowedHosts", "strategies"},
		},
		{
			name: "a v0.1 config that still uses upstreams has no strategies",
			config: func(f *fixture) string {
				return f.writeRawConfig("config.yaml", map[string]any{"upstreams": map[string]any{"a": map[string]any{"url": "https://x.test/mcp"}}})
			},
			want: []string{"config error:", "strategies"},
		},
		{
			name: "missing environment variables are named",
			config: func(f *fixture) string {
				return f.writeRawConfig("config.yaml", map[string]any{
					"allowedHosts": []string{"api.example.com"},
					"strategies":   map[string]any{"a": map[string]any{"command": "gen ${env:" + unsetVar + "}"}},
				})
			},
			want: []string{"config error:", unsetVar},
		},
		{
			name: "serve without allowedHosts",
			args: []string{"serve"},
			config: func(f *fixture) string {
				return f.writeRawConfig("config.yaml", map[string]any{"strategies": map[string]any{"a": map[string]any{"command": "g"}}})
			},
			want: []string{"config error: invalid config:", "allowedHosts"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(unsetVar, "")
			if err := os.Unsetenv(unsetVar); err != nil {
				t.Fatal(err)
			}
			f := newFixture(t)
			args := tt.args
			if args == nil {
				args = []string{"check"}
			}

			got := runCLI(t, nil, append(args, "-c", tt.config(f))...)

			if got.code != 2 {
				t.Fatalf("exit code %d, want 2\nstderr: %s", got.code, got.stderr)
			}
			contains(t, "stderr", got.stderr, tt.want)
			if strings.Contains(got.stdout+got.stderr, "listening on") {
				t.Error("must not start listening")
			}
		})
	}
}

func TestConfigPathSelection(t *testing.T) {
	t.Run("reads the path from MCP_AUTH_PROXY_CONFIG", func(t *testing.T) {
		f := newFixture(t)

		got := runCLI(t, map[string]string{configEnv: f.writeConfig()}, "check", "long")

		if got.code != 0 || !strings.Contains(got.stdout, "long: ok") {
			t.Fatalf("code %d\nstdout: %s\nstderr: %s", got.code, got.stdout, got.stderr)
		}
	})

	t.Run("prefers --config over MCP_AUTH_PROXY_CONFIG", func(t *testing.T) {
		f := newFixture(t)
		env := map[string]string{configEnv: filepath.Join(f.dir, "missing.yaml")}

		got := runCLI(t, env, "check", "long", "--config", f.writeConfig())

		if got.code != 0 || !strings.Contains(got.stdout, "long: ok") {
			t.Fatalf("code %d\nstdout: %s\nstderr: %s", got.code, got.stdout, got.stderr)
		}
	})

	t.Run("a bad MCP_AUTH_PROXY_CONFIG path is a config error", func(t *testing.T) {
		f := newFixture(t)

		got := runCLI(t, map[string]string{configEnv: filepath.Join(f.dir, "missing.yaml")}, "check")

		if got.code != 2 || !strings.Contains(got.stderr, "config error: cannot read config") {
			t.Fatalf("code %d stderr %q", got.code, got.stderr)
		}
	})

	t.Run("falls back to the default path", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)

		got := runCLI(t, nil, "check")

		if got.code != 2 || !strings.Contains(got.stderr, filepath.Join(home, ".config", "mcp-auth-proxy", "config.yaml")) {
			t.Fatalf("code %d stderr %q", got.code, got.stderr)
		}
	})
}

func TestEnvironmentReachesTheGenerator(t *testing.T) {
	t.Setenv("MCP_AUTH_PROXY_TEST_GREETING", "hello")
	f := newFixture(t)
	config := f.writeRawConfig("config.yaml", map[string]any{
		"allowedHosts": []string{"api.example.com"},
		"strategies": map[string]any{
			"env": map[string]any{
				"command": []string{"sh", "-c", `echo "$GREETING-padded-to-be-long-enough"`},
				"env":     map[string]any{"GREETING": "${env:MCP_AUTH_PROXY_TEST_GREETING}"},
			},
		},
	})

	got := runCLI(t, nil, "check", "-c", config)

	if got.code != 0 {
		t.Fatalf("exit code %d\nstdout: %s\nstderr: %s", got.code, got.stdout, got.stderr)
	}
	contains(t, "stdout", got.stdout, []string{"env: ok", "hello-... (30 chars)"})
}

func TestMask(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		{"empty", "", "(0 chars)"},
		{"short", "tok.1.1234567890", "(16 chars)"},
		{"one below the threshold", strings.Repeat("a", 23), "(23 chars)"},
		{"at the threshold", "abcdefghijklmnopqrstuvwx", "abcdef... (24 chars)"},
		{"long", longToken, "abcdef... (36 chars)"},
		{"multibyte counts characters", strings.Repeat("é", 24), "éééééé... (24 chars)"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mask(tt.value); got != tt.want {
				t.Errorf("mask(%q) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestDescribeDuration(t *testing.T) {
	tests := []struct {
		d    time.Duration
		want string
	}{
		{20 * time.Second, "20s"},
		{29 * time.Second, "29s"},
		{30 * time.Second, "1m"},
		{59*time.Minute + 59*time.Second, "60m"},
		{119 * time.Minute, "119m"},
		{120 * time.Minute, "2h"},
		{3 * time.Hour, "3h"},
		{-5 * time.Second, "-5s"},
	}
	for _, tt := range tests {
		t.Run(tt.d.String(), func(t *testing.T) {
			if got := describeDuration(tt.d); got != tt.want {
				t.Errorf("describeDuration(%v) = %q, want %q", tt.d, got, tt.want)
			}
		})
	}
}
