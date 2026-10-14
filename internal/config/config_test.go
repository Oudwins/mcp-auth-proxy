package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"
)

type raw = map[string]any

func minimal() raw {
	return raw{
		"allowedHosts": []any{"api.example.com"},
		"strategies":   raw{"a": raw{"command": "gen.sh"}},
	}
}

func withStrategy(extra raw) raw {
	strategy := raw{"command": "gen.sh"}
	for key, value := range extra {
		strategy[key] = value
	}
	cfg := minimal()
	cfg["strategies"] = raw{"a": strategy}
	return cfg
}

func withHosts(entries ...any) raw {
	cfg := minimal()
	cfg["allowedHosts"] = entries
	return cfg
}

func mustParse(t *testing.T, input any, baseDir string) *Config {
	t.Helper()
	cfg, err := Parse(input, baseDir)
	if err != nil {
		t.Fatalf("Parse returned an error: %v", err)
	}
	return cfg
}

func parseError(t *testing.T, input any) string {
	t.Helper()
	cfg, err := Parse(input, "/base")
	if err == nil {
		t.Fatalf("Parse succeeded, want an error (got %+v)", cfg)
	}
	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("error is %T, want *ConfigError", err)
	}
	return configErr.Error()
}

func expectError(t *testing.T, input any, patterns ...string) {
	t.Helper()
	message := parseError(t, input)
	for _, pattern := range patterns {
		if !regexp.MustCompile(pattern).MatchString(message) {
			t.Errorf("error does not match %q:\n%s", pattern, message)
		}
	}
}

func strategyA(t *testing.T, input raw) Strategy {
	t.Helper()
	return mustParse(t, input, "/base").Strategies["a"]
}

func TestDefaults(t *testing.T) {
	t.Run("fills in listen and logging defaults", func(t *testing.T) {
		cfg := mustParse(t, minimal(), "/base")

		if cfg.Listen != (Listen{Host: "127.0.0.1", Port: 7600}) {
			t.Errorf("Listen = %+v", cfg.Listen)
		}
		if cfg.LogLevel != "info" {
			t.Errorf("LogLevel = %q", cfg.LogLevel)
		}
		if cfg.MaxBodyBytes != 25*1024*1024 {
			t.Errorf("MaxBodyBytes = %d", cfg.MaxBodyBytes)
		}
		if !reflect.DeepEqual(cfg.AllowedHosts, []string{"api.example.com"}) {
			t.Errorf("AllowedHosts = %v", cfg.AllowedHosts)
		}
	})

	t.Run("fills in a partial listen block", func(t *testing.T) {
		withPort := minimal()
		withPort["listen"] = raw{"port": 9000}
		withHost := minimal()
		withHost["listen"] = raw{"host": "0.0.0.0"}
		nullListen := minimal()
		nullListen["listen"] = nil

		if got := mustParse(t, withPort, "/base").Listen; got != (Listen{Host: "127.0.0.1", Port: 9000}) {
			t.Errorf("port only: %+v", got)
		}
		if got := mustParse(t, withHost, "/base").Listen; got != (Listen{Host: "0.0.0.0", Port: 7600}) {
			t.Errorf("host only: %+v", got)
		}
		if got := mustParse(t, nullListen, "/base").Listen; got != (Listen{Host: "127.0.0.1", Port: 7600}) {
			t.Errorf("null: %+v", got)
		}
	})

	t.Run("fills in strategy defaults and resolves cwd against the config directory", func(t *testing.T) {
		got := mustParse(t, minimal(), "/base/dir").Strategies["a"]
		want := Strategy{
			Command:       []string{"/bin/sh", "-c", "gen.sh"},
			Output:        "token",
			TTL:           300 * time.Second,
			RefreshSkew:   60 * time.Second,
			RetryCooldown: 5 * time.Second,
			Timeout:       30 * time.Second,
			RetryOnStatus: []int{401},
			AllowedHosts:  []string{"api.example.com"},
			Cwd:           "/base/dir",
			Env:           map[string]string{},
		}

		if !reflect.DeepEqual(got, want) {
			t.Errorf("strategy = %+v\nwant     %+v", got, want)
		}
	})

	t.Run("resolves relative cwd values and keeps absolute ones", func(t *testing.T) {
		cfg := minimal()
		cfg["strategies"] = raw{
			"rel": raw{"command": "g", "cwd": "scripts"},
			"dot": raw{"command": "g", "cwd": "./nested/dir"},
			"abs": raw{"command": "g", "cwd": "/opt/gen"},
		}
		got := mustParse(t, cfg, "/base").Strategies

		for name, want := range map[string]string{"rel": "/base/scripts", "dot": "/base/nested/dir", "abs": "/opt/gen"} {
			if got[name].Cwd != want {
				t.Errorf("%s cwd = %q, want %q", name, got[name].Cwd, want)
			}
		}
	})

	t.Run("makes the cwd absolute when the base directory is relative", func(t *testing.T) {
		got := mustParse(t, minimal(), "relative/dir").Strategies["a"].Cwd

		if !filepath.IsAbs(got) || !strings.HasSuffix(got, filepath.FromSlash("relative/dir")) {
			t.Errorf("cwd = %q", got)
		}
	})

	t.Run("accepts both string and array commands", func(t *testing.T) {
		cfg := minimal()
		cfg["strategies"] = raw{
			"shell": raw{"command": "bash ./gen.sh"},
			"argv":  raw{"command": []any{"gcloud", "auth", "print-identity-token"}},
			"typed": raw{"command": []string{"echo", ""}},
		}
		got := mustParse(t, cfg, "/base").Strategies

		if want := []string{"/bin/sh", "-c", "bash ./gen.sh"}; !reflect.DeepEqual(got["shell"].Command, want) {
			t.Errorf("shell command = %v", got["shell"].Command)
		}
		if want := []string{"gcloud", "auth", "print-identity-token"}; !reflect.DeepEqual(got["argv"].Command, want) {
			t.Errorf("argv command = %v", got["argv"].Command)
		}
		if want := []string{"echo", ""}; !reflect.DeepEqual(got["typed"].Command, want) {
			t.Errorf("typed command = %v", got["typed"].Command)
		}
	})

	t.Run("accepts dotted and dashed strategy names", func(t *testing.T) {
		cfg := minimal()
		cfg["strategies"] = raw{"payload.cms-2_x": raw{"command": "g"}, "9lives": raw{"command": "g"}}

		mustParse(t, cfg, "/base")
	})

	t.Run("keeps explicit settings", func(t *testing.T) {
		cfg := withStrategy(raw{"output": "json", "retryOnStatus": []any{401, 403}, "env": raw{"K": "V"}})
		cfg["listen"] = raw{"host": "0.0.0.0", "port": 9000}
		cfg["logLevel"] = "debug"
		cfg["maxBodyBytes"] = 1024
		got := mustParse(t, cfg, "/base")

		if got.Listen != (Listen{Host: "0.0.0.0", Port: 9000}) || got.LogLevel != "debug" || got.MaxBodyBytes != 1024 {
			t.Errorf("settings = %+v", got)
		}
		strategy := got.Strategies["a"]
		if strategy.Output != "json" || !reflect.DeepEqual(strategy.RetryOnStatus, []int{401, 403}) ||
			!reflect.DeepEqual(strategy.Env, map[string]string{"K": "V"}) {
			t.Errorf("strategy = %+v", strategy)
		}
	})

	t.Run("allows an empty retryOnStatus list and an empty env value", func(t *testing.T) {
		strategy := strategyA(t, withStrategy(raw{"retryOnStatus": []any{}, "env": raw{"EMPTY": ""}}))

		if len(strategy.RetryOnStatus) != 0 || strategy.Env["EMPTY"] != "" {
			t.Errorf("strategy = %+v", strategy)
		}
	})

	t.Run("accepts whole floats where integers are expected", func(t *testing.T) {
		cfg := minimal()
		cfg["listen"] = raw{"port": 7601.0}

		if got := mustParse(t, cfg, "/base").Listen.Port; got != 7601 {
			t.Errorf("port = %d", got)
		}
	})

	t.Run("ends the default config path with the YAML file under ~/.config", func(t *testing.T) {
		want := filepath.Join(".config", "mcp-auth-proxy", "config.yaml")

		if got := DefaultPath(); !strings.HasSuffix(got, want) {
			t.Errorf("DefaultPath() = %q", got)
		}
	})
}

func TestDurations(t *testing.T) {
	t.Run("treats plain numbers as seconds", func(t *testing.T) {
		got := strategyA(t, withStrategy(raw{"ttl": 120, "timeout": 10, "refreshSkew": 30, "retryCooldown": 2.5}))

		if got.TTL != 120*time.Second || got.Timeout != 10*time.Second || got.RefreshSkew != 30*time.Second ||
			got.RetryCooldown != 2500*time.Millisecond {
			t.Errorf("durations = %v %v %v %v", got.TTL, got.Timeout, got.RefreshSkew, got.RetryCooldown)
		}
	})

	for _, tc := range []struct {
		text string
		want time.Duration
	}{
		{"500ms", 500 * time.Millisecond},
		{"30s", 30 * time.Second},
		{"55m", 55 * time.Minute},
		{"1h", time.Hour},
		{"2h", 2 * time.Hour},
		{"1.5m", 90 * time.Second},
		{"45", 45 * time.Second},
		{"10 s", 10 * time.Second},
		{" 7s ", 7 * time.Second},
		{"0.1s", 100 * time.Millisecond},
	} {
		t.Run("parses the duration "+tc.text, func(t *testing.T) {
			got := strategyA(t, withStrategy(raw{"ttl": tc.text, "retryCooldown": tc.text, "refreshSkew": tc.text, "timeout": tc.text}))

			if got.TTL != tc.want || got.RetryCooldown != tc.want || got.RefreshSkew != tc.want || got.Timeout != tc.want {
				t.Errorf("durations = %v %v %v %v, want %v", got.TTL, got.RetryCooldown, got.RefreshSkew, got.Timeout, tc.want)
			}
		})
	}

	t.Run("allows zero for refreshSkew and retryCooldown", func(t *testing.T) {
		got := strategyA(t, withStrategy(raw{"refreshSkew": 0, "retryCooldown": "0s"}))

		if got.RefreshSkew != 0 || got.RetryCooldown != 0 {
			t.Errorf("durations = %v %v", got.RefreshSkew, got.RetryCooldown)
		}
	})

	t.Run("requires ttl and timeout to be positive", func(t *testing.T) {
		expectError(t, withStrategy(raw{"ttl": 0}), `strategies\.a\.ttl: `)
		expectError(t, withStrategy(raw{"ttl": "0m"}), `strategies\.a\.ttl: `)
		expectError(t, withStrategy(raw{"timeout": 0}), `strategies\.a\.timeout: `)
	})

	for _, text := range []string{"soon", "5 minutes", "-5s", "1d", ""} {
		t.Run("rejects the duration "+text, func(t *testing.T) {
			expectError(t, withStrategy(raw{"ttl": text}), `strategies\.a\.ttl: `)
		})
	}

	t.Run("rejects negative numbers", func(t *testing.T) {
		expectError(t, withStrategy(raw{"refreshSkew": -1}), `strategies\.a\.refreshSkew: `)
		expectError(t, withStrategy(raw{"retryCooldown": -1}), `strategies\.a\.retryCooldown: `)
	})

	t.Run("rejects values that are neither numbers nor strings", func(t *testing.T) {
		expectError(t, withStrategy(raw{"ttl": true}), `strategies\.a\.ttl: `)
		expectError(t, withStrategy(raw{"ttl": []any{1}}), `strategies\.a\.ttl: `)
	})

	t.Run("rejects durations that overflow", func(t *testing.T) {
		expectError(t, withStrategy(raw{"ttl": "99999999999h"}), `strategies\.a\.ttl: `)
	})

	t.Run("names the offending value in the error", func(t *testing.T) {
		expectError(t, withStrategy(raw{"ttl": "soon"}), `"soon" is not a duration`)
	})
}

func TestAllowedHosts(t *testing.T) {
	t.Run("copies the global list into every strategy that does not override it", func(t *testing.T) {
		cfg := raw{
			"allowedHosts": []any{"*.example.com"},
			"strategies": raw{
				"inherit": raw{"command": "g"},
				"own":     raw{"command": "g", "allowedHosts": []any{"https://api.foo.dev"}},
			},
		}
		got := mustParse(t, cfg, "/base")

		if want := []string{"*.example.com"}; !reflect.DeepEqual(got.Strategies["inherit"].AllowedHosts, want) {
			t.Errorf("inherit = %v", got.Strategies["inherit"].AllowedHosts)
		}
		if want := []string{"https://api.foo.dev"}; !reflect.DeepEqual(got.Strategies["own"].AllowedHosts, want) {
			t.Errorf("own = %v", got.Strategies["own"].AllowedHosts)
		}
		if want := []string{"*.example.com"}; !reflect.DeepEqual(got.AllowedHosts, want) {
			t.Errorf("global = %v", got.AllowedHosts)
		}
	})

	t.Run("replaces rather than merges the global list", func(t *testing.T) {
		got := strategyA(t, withStrategy(raw{"allowedHosts": []any{"only.example.org"}}))

		if want := []string{"only.example.org"}; !reflect.DeepEqual(got.AllowedHosts, want) {
			t.Errorf("AllowedHosts = %v", got.AllowedHosts)
		}
	})

	for _, entry := range []string{
		"example.com",
		"https://example.com",
		"http://localhost:3000",
		"api.example.com:8443",
		"*.example.com",
		"https://*.example.com:8443",
		"127.0.0.1",
		"http://127.0.0.1:7000",
		"[::1]",
		"http://[::1]:8080",
		"localhost",
	} {
		t.Run("accepts the host entry "+entry, func(t *testing.T) {
			mustParse(t, withHosts(entry), "/base")
		})
	}

	for _, entry := range []string{
		"ftp://example.com",
		"example.com/path",
		"https://example.com/mcp",
		"exa mple.com",
		"",
		"*",
		"*example.com",
		"https://",
		"example.com:",
		"example.com:abc",
	} {
		t.Run("rejects the host entry "+entry, func(t *testing.T) {
			expectError(t, withHosts(entry), `allowedHosts\[0\]: `)
		})
	}

	t.Run("rejects wildcards without a domain and wildcards on IPs", func(t *testing.T) {
		expectError(t, withHosts("*.com"), `too broad`)
		expectError(t, withHosts("*.localhost"), `too broad`)
		expectError(t, withHosts("*.[::1]"), `too broad|IP address`)
	})

	t.Run("rejects non-string entries", func(t *testing.T) {
		expectError(t, withHosts("ok.example.com", 5), `allowedHosts\[1\]: expected a string`)
		expectError(t, withHosts("ok.example.com", nil), `allowedHosts\[1\]: `)
	})

	t.Run("rejects a host list that is not a list", func(t *testing.T) {
		cfg := minimal()
		cfg["allowedHosts"] = "example.com"

		expectError(t, cfg, `allowedHosts: expected a list`)
	})

	t.Run("reports the entry index in the path, globally and per strategy", func(t *testing.T) {
		expectError(t, withHosts("ok.example.com", "ftp://bad"), `allowedHosts\[1\]: .*ftp://bad`)
		expectError(t, withStrategy(raw{"allowedHosts": []any{"ok.example.com", "also.ok.com", "bad entry"}}),
			`strategies\.a\.allowedHosts\[2\]: .*bad entry`)
	})

	t.Run("requires a non-empty global list", func(t *testing.T) {
		withoutHosts := minimal()
		delete(withoutHosts, "allowedHosts")

		expectError(t, withoutHosts, `allowedHosts: .*at least one host`)
		expectError(t, withHosts(), `allowedHosts: .*at least one host`)
	})

	t.Run("rejects an empty per-strategy list instead of falling back to the global one", func(t *testing.T) {
		expectError(t, withStrategy(raw{"allowedHosts": []any{}}), `strategies\.a\.allowedHosts: `)
	})
}

func TestEnvironmentInterpolation(t *testing.T) {
	t.Run("substitutes variables in commands, env, cwd and host entries", func(t *testing.T) {
		t.Setenv("MCP_TEST_HOST", "api.test")
		t.Setenv("MCP_TEST_KEY", "abc")
		cfg := raw{
			"allowedHosts": []any{"https://${env:MCP_TEST_HOST}"},
			"strategies": raw{
				"a": raw{
					"command": []any{"gen", "${env:MCP_TEST_KEY}"},
					"env":     raw{"AUD": "${env:MCP_TEST_KEY}-aud"},
					"cwd":     "${env:MCP_TEST_KEY}-dir",
				},
				"b": raw{"command": "gen ${env:MCP_TEST_KEY}", "allowedHosts": []any{"${env:MCP_TEST_HOST}:8443"}},
			},
		}
		got := mustParse(t, cfg, "/base")

		if want := []string{"https://api.test"}; !reflect.DeepEqual(got.AllowedHosts, want) {
			t.Errorf("global hosts = %v", got.AllowedHosts)
		}
		a, b := got.Strategies["a"], got.Strategies["b"]
		if want := []string{"gen", "abc"}; !reflect.DeepEqual(a.Command, want) {
			t.Errorf("a command = %v", a.Command)
		}
		if want := map[string]string{"AUD": "abc-aud"}; !reflect.DeepEqual(a.Env, want) {
			t.Errorf("a env = %v", a.Env)
		}
		if a.Cwd != "/base/abc-dir" {
			t.Errorf("a cwd = %q", a.Cwd)
		}
		if want := []string{"/bin/sh", "-c", "gen abc"}; !reflect.DeepEqual(b.Command, want) {
			t.Errorf("b command = %v", b.Command)
		}
		if want := []string{"api.test:8443"}; !reflect.DeepEqual(b.AllowedHosts, want) {
			t.Errorf("b hosts = %v", b.AllowedHosts)
		}
	})

	t.Run("substitutes several references inside one string", func(t *testing.T) {
		t.Setenv("MCP_TEST_A", "x")
		t.Setenv("MCP_TEST_B", "y")

		got := strategyA(t, withStrategy(raw{"command": "run ${env:MCP_TEST_A}-${env:MCP_TEST_B}"}))

		if got.Command[2] != "run x-y" {
			t.Errorf("command = %v", got.Command)
		}
	})

	t.Run("accepts a variable that is set to the empty string", func(t *testing.T) {
		t.Setenv("MCP_TEST_EMPTY", "")

		got := strategyA(t, withStrategy(raw{"command": "run${env:MCP_TEST_EMPTY}"}))

		if got.Command[2] != "run" {
			t.Errorf("command = %v", got.Command)
		}
	})

	t.Run("leaves {{placeholders}} and plain dollar signs alone", func(t *testing.T) {
		got := strategyA(t, withStrategy(raw{"command": "echo {{token}} $HOME ${HOME}"}))

		if got.Command[2] != "echo {{token}} $HOME ${HOME}" {
			t.Errorf("command = %v", got.Command)
		}
	})

	t.Run("fails at startup and names every missing variable with its location", func(t *testing.T) {
		for _, name := range []string{"MCP_TEST_NOPE", "MCP_TEST_NOPE_TOO"} {
			t.Setenv(name, "")
			os.Unsetenv(name)
		}
		cfg := raw{
			"allowedHosts": []any{"${env:MCP_TEST_NOPE}"},
			"strategies": raw{
				"a": raw{"command": []any{"g", "${env:MCP_TEST_NOPE}"}, "env": raw{"K": "${env:MCP_TEST_NOPE_TOO}"}},
			},
		}

		message := parseError(t, cfg)

		for _, want := range []string{
			"MCP_TEST_NOPE (at config.allowedHosts[0])",
			"MCP_TEST_NOPE (at config.strategies.a.command[1])",
			"MCP_TEST_NOPE_TOO (at config.strategies.a.env.K)",
		} {
			if !strings.Contains(message, want) {
				t.Errorf("error does not mention %q:\n%s", want, message)
			}
		}
	})

	t.Run("reports missing variables in a stable order", func(t *testing.T) {
		os.Unsetenv("MCP_TEST_NOPE")
		cfg := raw{
			"allowedHosts": []any{"example.com"},
			"strategies": raw{
				"z": raw{"command": "${env:MCP_TEST_NOPE}"},
				"a": raw{"command": "${env:MCP_TEST_NOPE}"},
				"m": raw{"command": "${env:MCP_TEST_NOPE}"},
			},
		}

		first := parseError(t, cfg)

		for range 10 {
			if again := parseError(t, cfg); again != first {
				t.Fatalf("error changed between runs:\n%s\n%s", first, again)
			}
		}
	})
}

func TestValidation(t *testing.T) {
	t.Run("ignores unknown keys at every level", func(t *testing.T) {
		atRoot := minimal()
		atRoot["bogus"] = 1
		atRoot["upstreams"] = raw{"a": raw{"url": "https://x.test"}}
		inListen := minimal()
		inListen["listen"] = raw{"port": 1, "bogus": 1}

		mustParse(t, atRoot, "/base")
		mustParse(t, inListen, "/base")
		mustParse(t, withStrategy(raw{"bogus": 1, "params": raw{"aud": "x"}}), "/base")
	})

	t.Run("still reports real problems next to unknown keys", func(t *testing.T) {
		cfg := withStrategy(raw{"params": 1, "ttl": "soon"})
		cfg["bogus"] = 1

		expectError(t, cfg, `strategies\.a\.ttl: `)
	})

	t.Run("does not flag arbitrary keys in env or strategy names", func(t *testing.T) {
		cfg := withStrategy(raw{"env": raw{"ANY_KEY": "v", "another": "w"}})

		mustParse(t, cfg, "/base")
	})

	t.Run("requires at least one strategy and a command on each", func(t *testing.T) {
		noStrategies := raw{"allowedHosts": []any{"a.example.com"}}
		emptyStrategies := minimal()
		emptyStrategies["strategies"] = raw{}
		noCommand := minimal()
		noCommand["strategies"] = raw{"a": raw{}}
		nullStrategy := minimal()
		nullStrategy["strategies"] = raw{"a": nil}

		expectError(t, noStrategies, `strategies: .*at least one strategy`)
		expectError(t, emptyStrategies, `strategies: .*at least one strategy`)
		expectError(t, noCommand, `strategies\.a\.command: `)
		expectError(t, nullStrategy, `strategies\.a\.command: `)
	})

	for _, name := range []string{"has space", "../x", "-x", ".x", "_x", "a/b", "a:b", "{{x}}"} {
		t.Run("rejects the strategy name "+name, func(t *testing.T) {
			cfg := minimal()
			cfg["strategies"] = raw{name: raw{"command": "g"}}

			expectError(t, cfg, `letters, digits`)
		})
	}

	t.Run("rejects the wrong output mode and log level", func(t *testing.T) {
		badLevel := minimal()
		badLevel["logLevel"] = "trace"

		expectError(t, withStrategy(raw{"output": "headers"}), `strategies\.a\.output: `)
		expectError(t, badLevel, `logLevel: `)
	})

	t.Run("rejects empty commands", func(t *testing.T) {
		expectError(t, withStrategy(raw{"command": ""}), `strategies\.a\.command: `)
		expectError(t, withStrategy(raw{"command": []any{}}), `strategies\.a\.command: `)
	})

	t.Run("rejects commands of the wrong type", func(t *testing.T) {
		expectError(t, withStrategy(raw{"command": 5}), `strategies\.a\.command: `)
		expectError(t, withStrategy(raw{"command": []any{"g", 1}}), `strategies\.a\.command\[1\]: `)
	})

	t.Run("rejects bad numbers", func(t *testing.T) {
		withListen := func(port any) raw {
			cfg := minimal()
			cfg["listen"] = raw{"port": port}
			return cfg
		}
		zeroBody := minimal()
		zeroBody["maxBodyBytes"] = 0
		stringBody := minimal()
		stringBody["maxBodyBytes"] = "1024"

		expectError(t, withListen(70000), `listen\.port: `)
		expectError(t, withListen(-1), `listen\.port: `)
		expectError(t, withListen(1.5), `listen\.port: `)
		expectError(t, withListen("7600"), `listen\.port: `)
		expectError(t, zeroBody, `maxBodyBytes: `)
		expectError(t, stringBody, `maxBodyBytes: `)
		expectError(t, withStrategy(raw{"retryOnStatus": []any{42}}), `strategies\.a\.retryOnStatus\[0\]: `)
		expectError(t, withStrategy(raw{"retryOnStatus": []any{401, 600}}), `strategies\.a\.retryOnStatus\[1\]: `)
		expectError(t, withStrategy(raw{"retryOnStatus": 401}), `strategies\.a\.retryOnStatus: `)
	})

	t.Run("allows port 0 for an ephemeral port", func(t *testing.T) {
		cfg := minimal()
		cfg["listen"] = raw{"port": 0}

		if got := mustParse(t, cfg, "/base").Listen.Port; got != 0 {
			t.Errorf("port = %d", got)
		}
	})

	t.Run("rejects non-string env values", func(t *testing.T) {
		expectError(t, withStrategy(raw{"env": raw{"N": 1}}), `strategies\.a\.env\.N: `)
		expectError(t, withStrategy(raw{"env": []any{"A=1"}}), `strategies\.a\.env: `)
	})

	t.Run("rejects non-mapping roots", func(t *testing.T) {
		for name, input := range map[string]any{"null": nil, "list": []any{}, "string": "config", "number": 3} {
			t.Run(name, func(t *testing.T) {
				expectError(t, input, `(?m)^invalid config:\n {2}\(root\): `)
			})
		}
	})

	t.Run("rejects blocks of the wrong shape", func(t *testing.T) {
		badListen := minimal()
		badListen["listen"] = "localhost:7600"
		badStrategies := minimal()
		badStrategies["strategies"] = []any{"a"}

		expectError(t, badListen, `listen: expected a mapping`)
		expectError(t, badStrategies, `strategies: `)
		expectError(t, withStrategy(raw{"cwd": 1}), `strategies\.a\.cwd: expected a string`)
	})

	t.Run("accepts maps with non-string keys by stringifying them", func(t *testing.T) {
		cfg := map[any]any{"allowedHosts": []any{"a.example.com"}, "strategies": map[any]any{"a": map[any]any{"command": "g"}}}

		mustParse(t, cfg, "/base")
	})

	t.Run("formats errors as 'invalid config:' followed by one 'path: message' line per problem", func(t *testing.T) {
		cfg := raw{
			"allowedHosts": []any{"ftp://x"},
			"strategies":   raw{"a": raw{"command": "g", "ttl": "soon", "retryOnStatus": []any{42}}},
		}

		message := parseError(t, cfg)

		head, rest, _ := strings.Cut(message, "\n")
		if head != "invalid config:" {
			t.Errorf("header = %q", head)
		}
		lines := strings.Split(rest, "\n")
		if len(lines) < 3 {
			t.Errorf("got %d issue lines, want at least 3:\n%s", len(lines), message)
		}
		linePattern := regexp.MustCompile(`^ {2}\S+: .+`)
		for _, line := range lines {
			if !linePattern.MatchString(line) {
				t.Errorf("line %q is not 'path: message'", line)
			}
		}
		for _, pattern := range []string{
			`(?m)^ {2}allowedHosts\[0\]: `,
			`(?m)^ {2}strategies\.a\.ttl: `,
			`(?m)^ {2}strategies\.a\.retryOnStatus\[0\]: `,
		} {
			if !regexp.MustCompile(pattern).MatchString(message) {
				t.Errorf("error does not match %q:\n%s", pattern, message)
			}
		}
		if !sortedStrings(lines) {
			t.Errorf("issue lines are not sorted:\n%s", message)
		}
	})

	t.Run("produces the same message on every run", func(t *testing.T) {
		cfg := raw{
			"allowedHosts": []any{"ftp://x", "bad entry"},
			"bogus":        1,
			"strategies": raw{
				"b": raw{"command": 5, "extra": 1},
				"a": raw{"ttl": "soon", "params": 1},
			},
		}

		first := parseError(t, cfg)

		for range 20 {
			if again := parseError(t, cfg); again != first {
				t.Fatalf("error changed between runs:\n%s\n%s", first, again)
			}
		}
	})
}

func sortedStrings(values []string) bool {
	for i := 1; i < len(values); i++ {
		if values[i-1] > values[i] {
			return false
		}
	}
	return true
}

func writeFile(t *testing.T, path, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func loadError(t *testing.T, path string) string {
	t.Helper()
	cfg, err := Load(path)
	if err == nil {
		t.Fatalf("Load succeeded, want an error (got %+v)", cfg)
	}
	var configErr *ConfigError
	if !errors.As(err, &configErr) {
		t.Fatalf("error is %T, want *ConfigError", err)
	}
	return configErr.Error()
}

func TestLoad(t *testing.T) {
	t.Run("reads a YAML file and resolves cwd relative to it", func(t *testing.T) {
		dir := t.TempDir()
		file := writeFile(t, filepath.Join(dir, "nested", "config.yaml"), strings.Join([]string{
			"listen: {host: 127.0.0.1, port: 7601}",
			"allowedHosts:",
			`  - "*.example.com"`,
			`  - "https://api.foo.dev"`,
			"strategies:",
			"  my-strategy:",
			"    command: [gcloud, auth, print-identity-token]",
			"    ttl: 55m",
			"    retryCooldown: 500ms",
			"    cwd: ./scripts",
			"    allowedHosts: [only.example.org]",
			"  second:",
			`    command: "bash ./gen.sh"`,
			"",
		}, "\n"))

		cfg, err := Load(file)
		if err != nil {
			t.Fatal(err)
		}

		if cfg.Listen.Port != 7601 {
			t.Errorf("port = %d", cfg.Listen.Port)
		}
		mine := cfg.Strategies["my-strategy"]
		if want := []string{"gcloud", "auth", "print-identity-token"}; !reflect.DeepEqual(mine.Command, want) {
			t.Errorf("command = %v", mine.Command)
		}
		if mine.TTL != 55*time.Minute || mine.RetryCooldown != 500*time.Millisecond {
			t.Errorf("durations = %v %v", mine.TTL, mine.RetryCooldown)
		}
		if want := filepath.Join(dir, "nested", "scripts"); mine.Cwd != want {
			t.Errorf("cwd = %q, want %q", mine.Cwd, want)
		}
		if want := []string{"only.example.org"}; !reflect.DeepEqual(mine.AllowedHosts, want) {
			t.Errorf("hosts = %v", mine.AllowedHosts)
		}
		second := cfg.Strategies["second"]
		if want := []string{"/bin/sh", "-c", "bash ./gen.sh"}; !reflect.DeepEqual(second.Command, want) {
			t.Errorf("second command = %v", second.Command)
		}
		if want := filepath.Join(dir, "nested"); second.Cwd != want {
			t.Errorf("second cwd = %q, want %q", second.Cwd, want)
		}
		if want := []string{"*.example.com", "https://api.foo.dev"}; !reflect.DeepEqual(second.AllowedHosts, want) {
			t.Errorf("second hosts = %v", second.AllowedHosts)
		}
	})

	t.Run("reads JSON as a subset of YAML", func(t *testing.T) {
		file := writeFile(t, filepath.Join(t.TempDir(), "config.json"),
			`{"allowedHosts": ["api.example.com"], "listen": {"port": 0}, "maxBodyBytes": 2048, "strategies": {"a": {"command": "gen.sh", "ttl": 90}}}`)

		cfg, err := Load(file)
		if err != nil {
			t.Fatal(err)
		}

		if got := cfg.Strategies["a"]; got.Command[2] != "gen.sh" || got.TTL != 90*time.Second {
			t.Errorf("strategy = %+v", got)
		}
		if cfg.Listen.Port != 0 || cfg.MaxBodyBytes != 2048 {
			t.Errorf("config = %+v", cfg)
		}
	})

	t.Run("interpolates environment variables from file contents", func(t *testing.T) {
		t.Setenv("MCP_TEST_FILE_HOST", "from-env.example.com")
		file := writeFile(t, filepath.Join(t.TempDir(), "config.yaml"),
			"allowedHosts: [\"${env:MCP_TEST_FILE_HOST}\"]\nstrategies:\n  a: {command: g}\n")

		cfg, err := Load(file)
		if err != nil {
			t.Fatal(err)
		}

		if want := []string{"from-env.example.com"}; !reflect.DeepEqual(cfg.AllowedHosts, want) {
			t.Errorf("hosts = %v", cfg.AllowedHosts)
		}
	})

	t.Run("ignores unknown keys in a file", func(t *testing.T) {
		file := writeFile(t, filepath.Join(t.TempDir(), "config.yaml"),
			"allowedHosts: [a.example.com]\nstrategies:\n  payload:\n    command: g\n    params: {aud: x}\n")

		cfg, err := Load(file)
		if err != nil {
			t.Fatalf("Load: %v", err)
		}
		if _, ok := cfg.Strategies["payload"]; !ok {
			t.Errorf("strategies = %v", cfg.Strategies)
		}
	})

	t.Run("reports a missing file as a ConfigError", func(t *testing.T) {
		message := loadError(t, filepath.Join(t.TempDir(), "missing.yaml"))

		if !strings.Contains(message, "cannot read config") {
			t.Errorf("error = %s", message)
		}
	})

	t.Run("reports malformed YAML as a ConfigError", func(t *testing.T) {
		file := writeFile(t, filepath.Join(t.TempDir(), "config.yaml"), "strategies: [unclosed\n  a: {")

		message := loadError(t, file)

		if !strings.Contains(message, "not valid YAML") {
			t.Errorf("error = %s", message)
		}
	})

	t.Run("reports an empty file as an invalid config", func(t *testing.T) {
		file := writeFile(t, filepath.Join(t.TempDir(), "config.yaml"), "")

		message := loadError(t, file)

		if !strings.HasPrefix(message, "invalid config:") {
			t.Errorf("error = %s", message)
		}
	})

	t.Run("reports a non-mapping document as an invalid config", func(t *testing.T) {
		file := writeFile(t, filepath.Join(t.TempDir(), "config.yaml"), "- just\n- a list\n")

		message := loadError(t, file)

		if !strings.Contains(message, "(root)") {
			t.Errorf("error = %s", message)
		}
	})
}

func TestStrategyNames(t *testing.T) {
	cfg := minimal()
	cfg["strategies"] = raw{"zeta": raw{"command": "g"}, "alpha": raw{"command": "g"}, "mid.2": raw{"command": "g"}}

	got := mustParse(t, cfg, "/base").StrategyNames()

	if want := []string{"alpha", "mid.2", "zeta"}; !reflect.DeepEqual(got, want) {
		t.Errorf("StrategyNames() = %v, want %v", got, want)
	}
}
