package auth

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/config"
)

var (
	testNow    = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	nowSeconds = testNow.Unix()
)

const daySeconds = 24 * 60 * 60

func makeStrategy(mods ...func(*config.Strategy)) config.Strategy {
	s := config.Strategy{
		Command:       []string{"true"},
		Output:        "token",
		TTL:           300 * time.Second,
		RefreshSkew:   60 * time.Second,
		RetryCooldown: 5 * time.Second,
		Timeout:       30 * time.Second,
		RetryOnStatus: []int{401},
		AllowedHosts:  []string{"example.com"},
		Env:           map[string]string{},
		Cwd:           "/tmp",
	}
	for _, mod := range mods {
		mod(&s)
	}
	return s
}

func fakeJwt(expSeconds int64) string {
	encode := func(v any) string {
		raw, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(raw)
	}
	return encode(map[string]any{"alg": "none"}) + "." + encode(map[string]any{"exp": expSeconds}) + ".signature"
}

func jsonOf(body any) string {
	raw, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func values(kv map[string]string, extra map[string]any) string {
	body := map[string]any{"values": kv}
	for k, v := range extra {
		body[k] = v
	}
	return jsonOf(body)
}

func parseJSON(t *testing.T, stdout string, ttl time.Duration) Parsed {
	t.Helper()
	got, err := ParseOutput(stdout, "json", ttl, testNow)
	if err != nil {
		t.Fatalf("ParseOutput(%q) failed: %v", stdout, err)
	}
	return got
}

func parseToken(t *testing.T, stdout string, ttl time.Duration) Parsed {
	t.Helper()
	got, err := ParseOutput(stdout, "token", ttl, testNow)
	if err != nil {
		t.Fatalf("ParseOutput(%q) failed: %v", stdout, err)
	}
	return got
}

func parseMessage(t *testing.T, stdout, output string) string {
	t.Helper()
	_, err := ParseOutput(stdout, output, 300*time.Second, testNow)
	if err == nil {
		t.Fatalf("ParseOutput(%q, %q) succeeded, expected an error", stdout, output)
	}
	var ce *CommandError
	if !errors.As(err, &ce) {
		t.Fatalf("error %T is not a *CommandError", err)
	}
	return err.Error()
}

func expectMatch(t *testing.T, message, pattern string) {
	t.Helper()
	if !strings.Contains(message, pattern) {
		t.Errorf("message %q does not contain %q", message, pattern)
	}
}

func expectExpiry(t *testing.T, got Parsed, wantMs int64, wantSource string) {
	t.Helper()
	if got.ExpiresAt.UnixMilli() != wantMs {
		t.Errorf("ExpiresAt = %d, want %d", got.ExpiresAt.UnixMilli(), wantMs)
	}
	if got.ExpirySource != wantSource {
		t.Errorf("ExpirySource = %q, want %q", got.ExpirySource, wantSource)
	}
}

func TestParseOutputExpiryResolution(t *testing.T) {
	nowMs := testNow.UnixMilli()
	x := map[string]string{"x": "v"}

	tests := []struct {
		name       string
		stdout     string
		ttl        time.Duration
		wantMs     int64
		wantSource string
	}{
		{"expiresAt as epoch seconds", values(x, map[string]any{"expiresAt": nowSeconds + 600}), 300 * time.Second, nowMs + 600_000, "output"},
		{"expiresAt as fractional epoch seconds", values(x, map[string]any{"expiresAt": float64(nowSeconds) + 600.5}), 300 * time.Second, nowMs + 600_500, "output"},
		{"expiresAt as ISO timestamp", values(x, map[string]any{"expiresAt": "2026-01-01T00:10:00Z"}), 300 * time.Second, nowMs + 600_000, "output"},
		{"expiresAt as ISO timestamp with offset", values(x, map[string]any{"expiresAt": "2026-01-01T01:10:00+01:00"}), 300 * time.Second, nowMs + 600_000, "output"},
		{"expiresAt as ISO timestamp with fraction", values(x, map[string]any{"expiresAt": "2026-01-01T00:10:00.250Z"}), 300 * time.Second, nowMs + 600_250, "output"},
		{"expiresInSeconds relative to now", values(x, map[string]any{"expiresInSeconds": 120}), 300 * time.Second, nowMs + 120_000, "output"},
		{"expiresAt preferred over expiresInSeconds", values(x, map[string]any{"expiresAt": nowSeconds + 60, "expiresInSeconds": 500}), 300 * time.Second, nowMs + 60_000, "output"},
		{
			"explicit expiry preferred over a JWT exp claim",
			values(map[string]string{"auth": "Bearer " + fakeJwt(nowSeconds+10)}, map[string]any{"expiresInSeconds": 500}),
			300 * time.Second, nowMs + 500_000, "output",
		},
		{
			"exp from a JWT value with a scheme",
			values(map[string]string{"auth": "Bearer " + fakeJwt(nowSeconds+900)}, nil),
			300 * time.Second, nowMs + 900_000, "jwt",
		},
		{
			"exp from a raw JWT value",
			values(map[string]string{"token": fakeJwt(nowSeconds + 900)}, nil),
			300 * time.Second, nowMs + 900_000, "jwt",
		},
		{
			"earliest exp when several values carry a JWT",
			values(map[string]string{
				"access": "Bearer " + fakeJwt(nowSeconds+900),
				"proxy":  "Bearer " + fakeJwt(nowSeconds+300),
				"opaque": "not-a-jwt",
			}, nil),
			300 * time.Second, nowMs + 300_000, "jwt",
		},
		{"ttl for opaque tokens", values(map[string]string{"x": "opaque"}, nil), 42 * time.Second, nowMs + 42_000, "ttl"},
		{"ttl for a dotted value whose payload is not JSON", values(map[string]string{"x": "a.b.c"}, nil), 42 * time.Second, nowMs + 42_000, "ttl"},
		{"ttl for a JWT whose exp is not a number", values(map[string]string{"x": "aaa." + base64.RawURLEncoding.EncodeToString([]byte(`{"exp":"soon"}`)) + ".c"}, nil), 42 * time.Second, nowMs + 42_000, "ttl"},
		{"ttl for a JWT payload that is not an object", values(map[string]string{"x": "aaa." + base64.RawURLEncoding.EncodeToString([]byte(`[1]`)) + ".c"}, nil), 42 * time.Second, nowMs + 42_000, "ttl"},
		{"ttl for a four part dotted value", values(map[string]string{"x": "a.b.c.d"}, nil), 42 * time.Second, nowMs + 42_000, "ttl"},
		{
			"numeric expiresAt just under the milliseconds threshold",
			values(x, map[string]any{"expiresAt": nowSeconds + 399*daySeconds}),
			300 * time.Second, nowMs + 399*daySeconds*1000, "output",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectExpiry(t, parseJSON(t, tt.stdout, tt.ttl), tt.wantMs, tt.wantSource)
		})
	}
}

func TestParseOutputExpiryErrors(t *testing.T) {
	x := map[string]string{"x": "v"}
	tests := []struct {
		name    string
		stdout  string
		pattern string
	}{
		{"expiresAt that looks like milliseconds", values(x, map[string]any{"expiresAt": testNow.UnixMilli() + 600_000}), "milliseconds"},
		{"expiresAt string that is not a date", values(x, map[string]any{"expiresAt": "tomorrow-ish"}), "ISO 8601"},
		{"empty expiresAt string", values(x, map[string]any{"expiresAt": ""}), "ISO 8601"},
		{"negative expiresInSeconds", values(x, map[string]any{"expiresInSeconds": -5}), "wrong shape"},
		{"zero expiresInSeconds", values(x, map[string]any{"expiresInSeconds": 0}), "wrong shape"},
		{"expiresInSeconds that is a string", values(x, map[string]any{"expiresInSeconds": "10"}), "wrong shape"},
		{"expiresAt that is a boolean", values(x, map[string]any{"expiresAt": true}), "wrong shape"},
		{"expiresAt that is null", values(x, map[string]any{"expiresAt": nil}), "wrong shape"},
		{"expired epoch expiresAt", values(x, map[string]any{"expiresAt": nowSeconds - 1}), "already expired"},
		{"expiresAt exactly now", values(x, map[string]any{"expiresAt": nowSeconds}), "already expired"},
		{"expired ISO expiresAt", values(x, map[string]any{"expiresAt": "2025-12-31T23:59:00Z"}), "already expired"},
		{"expired JWT", values(map[string]string{"auth": "Bearer " + fakeJwt(nowSeconds-60)}, nil), "already expired"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expectMatch(t, parseMessage(t, tt.stdout, "json"), tt.pattern)
		})
	}
}

func TestParseOutputJSON(t *testing.T) {
	t.Run("returns the values", func(t *testing.T) {
		got := parseJSON(t, values(map[string]string{"token": "abc", "user_2": "me@example.com"}, nil), 300*time.Second)
		want := map[string]string{"token": "abc", "user_2": "me@example.com"}
		if !reflect.DeepEqual(got.Values, want) {
			t.Errorf("Values = %v, want %v", got.Values, want)
		}
	})

	t.Run("ignores surrounding whitespace", func(t *testing.T) {
		got := parseJSON(t, "\n  "+values(map[string]string{"x": "v"}, nil)+"  \n\n", 300*time.Second)
		if !reflect.DeepEqual(got.Values, map[string]string{"x": "v"}) {
			t.Errorf("Values = %v", got.Values)
		}
	})

	t.Run("keeps inner whitespace in values", func(t *testing.T) {
		got := parseJSON(t, values(map[string]string{"auth": "Bearer abc"}, nil), 300*time.Second)
		if got.Values["auth"] != "Bearer abc" {
			t.Errorf("Values = %v", got.Values)
		}
	})

	t.Run("accepts underscores and digits in value names", func(t *testing.T) {
		got := parseJSON(t, values(map[string]string{"_a": "1", "B_2": "2", "camelCase9": "3"}, nil), 300*time.Second)
		want := map[string]string{"_a": "1", "B_2": "2", "camelCase9": "3"}
		if !reflect.DeepEqual(got.Values, want) {
			t.Errorf("Values = %v, want %v", got.Values, want)
		}
	})

	errorCases := []struct {
		name    string
		stdout  string
		pattern string
	}{
		{"empty output", "  \n", "nothing"},
		{"not JSON, pointing at output token", "not json", "not valid JSON"},
		{"not JSON hint mentions token", "not json", `output "token"`},
		{"truncated JSON", `{"values": {"x": "v"}`, "not valid JSON"},
		{"trailing data after the object", `{"values": {"x": "v"}} {"values": {"x": "w"}}`, "not valid JSON"},
		{"trailing garbage after the object", `{"values": {"x": "v"}} oops`, "not valid JSON"},
		{"JSON string", `"just-a-string"`, "wrong shape"},
		{"JSON array", "[1, 2]", "wrong shape"},
		{"JSON null", "null", "wrong shape"},
		{"JSON number", "5", "wrong shape"},
		{"old headers key", jsonOf(map[string]any{"headers": map[string]string{"Authorization": "Bearer secret-xyz"}}), "wrong shape"},
		{"unknown top-level key", values(map[string]string{"x": "v"}, map[string]any{"extra": 1}), "wrong shape"},
		{"unknown top-level key is named", values(map[string]string{"x": "v"}, map[string]any{"extra": 1}), "extra"},
		{"missing values key", jsonOf(map[string]any{"expiresInSeconds": 10}), "wrong shape"},
		{"values that is not an object", jsonOf(map[string]any{"values": "abc"}), "wrong shape"},
		{"null values", jsonOf(map[string]any{"values": nil}), "wrong shape"},
		{"non-string value", jsonOf(map[string]any{"values": map[string]any{"x": 5}}), "wrong shape"},
		{"null value", jsonOf(map[string]any{"values": map[string]any{"x": nil}}), "wrong shape"},
		{"empty values object", jsonOf(map[string]any{"values": map[string]string{}}), "no values"},
		{"empty value", values(map[string]string{"x": ""}, nil), "empty value"},
		{"empty value names the key", values(map[string]string{"x": ""}, nil), `"x"`},
	}
	for _, tt := range errorCases {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			expectMatch(t, parseMessage(t, tt.stdout, "json"), tt.pattern)
		})
	}

	t.Run("does not echo non-JSON output in the error", func(t *testing.T) {
		for _, stdout := range []string{"super-secret-token-123", `{"values": oops secret-xyz}`} {
			if message := parseMessage(t, stdout, "json"); strings.Contains(message, "secret") {
				t.Errorf("message %q echoes the output", message)
			}
		}
	})

	t.Run("does not echo values from output with the wrong shape", func(t *testing.T) {
		message := parseMessage(t, jsonOf(map[string]any{"values": map[string]any{"x": 5}, "extra": "secret-xyz"}), "json")
		expectMatch(t, message, "wrong shape")
		if strings.Contains(message, "secret-xyz") {
			t.Errorf("message %q echoes a value", message)
		}
	})

	t.Run("does not echo values containing control characters", func(t *testing.T) {
		message := parseMessage(t, values(map[string]string{"x": "secret-xyz\n"}, nil), "json")
		if strings.Contains(message, "secret-xyz") {
			t.Errorf("message %q echoes a value", message)
		}
	})

	t.Run("rejects invalid value names", func(t *testing.T) {
		for _, name := range []string{"bad name", "1abc", "a-b", "a.b", "", "{{x}}", "a\n"} {
			message := parseMessage(t, values(map[string]string{name: "v"}, nil), "json")
			expectMatch(t, message, "invalid value name")
		}
	})

	t.Run("rejects values containing control characters", func(t *testing.T) {
		for _, value := range []string{"a\r\nInjected: 1", "a\nb", "a\tb", "a\x00b", "a\x7fb", "a\x1bb"} {
			message := parseMessage(t, values(map[string]string{"x": value}, nil), "json")
			expectMatch(t, message, "control characters")
		}
	})

	t.Run("reports the first invalid value in name order", func(t *testing.T) {
		message := parseMessage(t, values(map[string]string{"b": "", "a": "x\ny"}, nil), "json")
		expectMatch(t, message, `"a"`)
	})

	t.Run("reports every shape issue", func(t *testing.T) {
		message := parseMessage(t, `{"values":{"a":1,"b":2},"extra":true,"expiresInSeconds":-1}`, "json")
		for _, want := range []string{"values.a", "values.b", "expiresInSeconds", "extra"} {
			expectMatch(t, message, want)
		}
	})

	t.Run("returned errors are CommandError values", func(t *testing.T) {
		_, err := ParseOutput("", "json", time.Second, testNow)
		var ce *CommandError
		if !errors.As(err, &ce) || ce.Message != err.Error() {
			t.Errorf("err = %#v", err)
		}
	})
}

func TestParseOutputToken(t *testing.T) {
	t.Run("returns the token with the ttl expiry", func(t *testing.T) {
		got := parseToken(t, "abc123\n", 300*time.Second)
		if !reflect.DeepEqual(got.Values, map[string]string{"token": "abc123"}) {
			t.Errorf("Values = %v", got.Values)
		}
		expectExpiry(t, got, testNow.UnixMilli()+300_000, "ttl")
	})

	t.Run("uses the configured ttl", func(t *testing.T) {
		expectExpiry(t, parseToken(t, "abc", 42*time.Second), testNow.UnixMilli()+42_000, "ttl")
	})

	t.Run("detects JWT expiry on a bare token", func(t *testing.T) {
		expectExpiry(t, parseToken(t, fakeJwt(nowSeconds+900), 300*time.Second), testNow.UnixMilli()+900_000, "jwt")
	})

	t.Run("does not treat JSON as a structured response", func(t *testing.T) {
		got := parseToken(t, `{"values":{"token":"abc"}}`, 300*time.Second)
		if got.Values["token"] != `{"values":{"token":"abc"}}` {
			t.Errorf("Values = %v", got.Values)
		}
	})

	t.Run("replaces invalid UTF-8 instead of passing raw bytes", func(t *testing.T) {
		got := parseToken(t, "ab\xffcd", 300*time.Second)
		if got.Values["token"] != "ab"+string(rune(0xfffd))+"cd" {
			t.Errorf("token = %q", got.Values["token"])
		}
	})

	errorCases := []struct {
		name    string
		stdout  string
		pattern string
	}{
		{"already expired JWT", fakeJwt(nowSeconds - 60), "already expired"},
		{"empty output", "\n", "nothing"},
		{"scheme plus token", "Bearer abc", "single token"},
		{"two lines", "abc\ndef", "single token"},
		{"non-breaking space inside", "abc" + string(rune(0xa0)) + "def", "single token"},
		{"control characters", "ab\x01cd", "control characters"},
		{"DEL", "ab\x7fcd", "control characters"},
	}
	for _, tt := range errorCases {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			expectMatch(t, parseMessage(t, tt.stdout, "token"), tt.pattern)
		})
	}

	t.Run("trims unicode whitespace around the token", func(t *testing.T) {
		padded := string(rune(0xfeff)) + string(rune(0xa0)) + "abc" + string(rune(0x2003)) + "\n"
		got := parseToken(t, padded, 300*time.Second)
		if got.Values["token"] != "abc" {
			t.Errorf("token = %q", got.Values["token"])
		}
	})
}

func TestParseOutputExpiresAtIsUTC(t *testing.T) {
	got := parseJSON(t, values(map[string]string{"x": "v"}, map[string]any{"expiresInSeconds": 1}), time.Second)
	if got.ExpiresAt.Location() != time.UTC {
		t.Errorf("location = %v, want UTC", got.ExpiresAt.Location())
	}
	if want := fmt.Sprint(testNow.Add(time.Second)); got.ExpiresAt.String() != want {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, want)
	}
}
