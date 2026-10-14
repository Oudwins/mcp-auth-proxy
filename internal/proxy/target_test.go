package proxy

import (
	"errors"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Oudwins/mcp-auth-proxy/internal/auth"
	"github.com/Oudwins/mcp-auth-proxy/internal/template"
)

func TestParseTargetValid(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
		want targetTemplate
	}{
		{"full url", "http://127.0.0.1:8080/mcp?x=1", targetTemplate{"http", "127.0.0.1:8080", "/mcp", "x=1"}},
		{"upper-case scheme is lowered", "HTTPS://Example.com", targetTemplate{"https", "Example.com", "", ""}},
		{"surrounding whitespace is trimmed", "  http://a.b/x  \n", targetTemplate{"http", "a.b", "/x", ""}},
		{"ipv6 with port", "http://[::1]:3000/p", targetTemplate{"http", "[::1]:3000", "/p", ""}},
		{"placeholders in path and query", "http://h/p/{{token}}?q={{token}}", targetTemplate{"http", "h", "/p/{{token}}", "q={{token}}"}},
		{"empty query", "http://h/x?", targetTemplate{"http", "h", "/x", ""}},
		{"single character host", "http://a", targetTemplate{"http", "a", "", ""}},
		{"max port", "http://h:65535/", targetTemplate{"http", "h:65535", "/", ""}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseTarget(tc.raw)
			if err != nil {
				t.Fatalf("parseTarget(%q) failed: %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("parseTarget(%q) = %+v, want %+v", tc.raw, got, tc.want)
			}
		})
	}
}

func TestParseTargetInvalid(t *testing.T) {
	t.Parallel()
	const generic = "x-proxy-target must be an absolute http(s) URL without a fragment"
	cases := []struct {
		raw     string
		message string
	}{
		{"", generic},
		{"not a url", generic},
		{"/relative", generic},
		{"ftp://h/x", generic},
		{"http:/h/x", generic},
		{"http://h/x#frag", generic},
		{"http://h/#", generic},
		{"httpſ://h/x", generic},
		{"http://{{token}}/x", "placeholders are not allowed in the scheme or host of the target"},
		{"http://h:{{port}}/x", "placeholders are not allowed in the scheme or host of the target"},
		{"http:///x", `"" is not a valid host[:port]`},
		{"http://a@b/x", `"a@b" is not a valid host[:port]`},
		{"http://user:pass@h/x", `"user:pass@h" is not a valid host[:port]`},
		{"http://127.0.0.1:123456/x", `"127.0.0.1:123456" is not a valid host[:port]`},
		{"http://h:/x", `"h:" is not a valid host[:port]`},
		{"http://-bad/x", `"-bad" is not a valid host[:port]`},
		{"http://bad-/x", `"bad-" is not a valid host[:port]`},
		{"http://ba d/x", `"ba d" is not a valid host[:port]`},
		{`http://h\@evil/x`, `"h\\@evil" is not a valid host[:port]`},
		{"http://[::1/x", `"[::1" is not a valid host[:port]`},
		{"http://hé/x", `"hé" is not a valid host[:port]`},
	}
	for _, tc := range cases {
		t.Run(tc.raw, func(t *testing.T) {
			t.Parallel()
			_, err := parseTarget(tc.raw)
			var reqErr *requestError
			if !errors.As(err, &reqErr) {
				t.Fatalf("parseTarget(%q) error = %v, want *requestError", tc.raw, err)
			}
			if reqErr.status != http.StatusBadRequest || reqErr.code != "invalid_target" {
				t.Errorf("status/code = %d %s", reqErr.status, reqErr.code)
			}
			if reqErr.message != tc.message {
				t.Errorf("message = %q, want %q", reqErr.message, tc.message)
			}
		})
	}
}

func TestBuildTarget(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name   string
		target string
		suffix suffix
		values map[string]string
		want   string
		host   string
	}{
		{"plain target", "http://h.test/mcp", suffix{}, nil, "/mcp", "h.test"},
		{"empty path becomes root", "http://h.test", suffix{}, nil, "/", "h.test"},
		{"values are component-encoded in the path", "http://h.test/p/{{a}}", suffix{}, map[string]string{"a": "x y/z?w"}, "/p/x%20y%2Fz%3Fw", "h.test"},
		{"values are component-encoded in the query", "http://h.test/p?t={{a}}&u=1", suffix{}, map[string]string{"a": "a&b=c"}, "/p?t=a%26b%3Dc&u=1", "h.test"},
		{"unicode values are utf-8 encoded", "http://h.test/{{a}}", suffix{}, map[string]string{"a": "é"}, "/%C3%A9", "h.test"},
		{"escaped slash in the suffix is preserved", "http://h.test/mcp", suffix{path: "/a%2Fb/c%20d"}, nil, "/mcp/a%2Fb/c%20d", "h.test"},
		{"suffix path is appended after trimming trailing slashes", "http://h.test/mcp///", suffix{path: "/x"}, nil, "/mcp/x", "h.test"},
		{"trailing slash is kept without a suffix", "http://h.test/mcp/", suffix{}, nil, "/mcp/", "h.test"},
		{"queries are merged with the target first", "http://h.test/p?a=1", suffix{path: "/x", query: "b=2&c=3"}, nil, "/p/x?a=1&b=2&c=3", "h.test"},
		{"suffix query alone", "http://h.test/p", suffix{query: "b=2"}, nil, "/p?b=2", "h.test"},
		{"encoded query is not double-encoded", "http://h.test/p", suffix{query: "e=f%26g"}, nil, "/p?e=f%26g", "h.test"},
		{"raw unsafe query bytes are sanitized", "http://h.test/p", suffix{query: "a=b c&d='e'&f=é"}, nil, "/p?a=b%20c&d=%27e%27&f=%C3%A9", "h.test"},
		{"raw unsafe path bytes are sanitized", "http://h.test/p", suffix{path: "/é x\"<>"}, nil, "/p/%C3%A9%20x%22%3C%3E", "h.test"},
		{"host is lowercased", "HTTP://EXAMPLE.com:8080/x", suffix{}, nil, "/x", "example.com:8080"},
		{"default http port is dropped", "http://Example.com:80/x", suffix{}, nil, "/x", "example.com"},
		{"default https port is dropped", "https://example.com:443/x", suffix{}, nil, "/x", "example.com"},
		{"non-default port is kept", "https://example.com:80/x", suffix{}, nil, "/x", "example.com:80"},
		{"ipv6 default port is dropped and bracketed", "http://[::1]:80/x", suffix{}, nil, "/x", "[::1]"},
		{"escape sequence stays literal", `http://h.test/{{a}}\{{a}}`, suffix{}, map[string]string{"a": "v"}, "/v%7B%7Ba%7D%7D", "h.test"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			parsed, err := parseTarget(tc.target)
			if err != nil {
				t.Fatal(err)
			}
			u, err := buildTarget(parsed, tc.suffix, tc.values)
			if err != nil {
				t.Fatalf("buildTarget failed: %v", err)
			}
			if got := u.RequestURI(); got != tc.want {
				t.Errorf("RequestURI = %q, want %q", got, tc.want)
			}
			if u.Host != tc.host {
				t.Errorf("host = %q, want %q", u.Host, tc.host)
			}
			if u.Scheme != parsed.scheme {
				t.Errorf("scheme = %q", u.Scheme)
			}
		})
	}
}

func TestBuildTargetErrors(t *testing.T) {
	t.Parallel()

	t.Run("unknown placeholder in the path", func(t *testing.T) {
		t.Parallel()
		parsed, _ := parseTarget("http://h.test/{{nope}}")
		_, err := buildTarget(parsed, suffix{}, map[string]string{"token": "x"})
		var placeholder *template.PlaceholderError
		if !errors.As(err, &placeholder) || !reflect.DeepEqual(placeholder.Missing, []string{"nope"}) || !reflect.DeepEqual(placeholder.Available, []string{"token"}) {
			t.Fatalf("error = %#v", err)
		}
	})

	t.Run("unknown placeholder in the query", func(t *testing.T) {
		t.Parallel()
		parsed, _ := parseTarget("http://h.test/?q={{nope}}")
		_, err := buildTarget(parsed, suffix{}, nil)
		var placeholder *template.PlaceholderError
		if !errors.As(err, &placeholder) {
			t.Fatalf("error = %#v", err)
		}
	})

	t.Run("invalid escape in the request path", func(t *testing.T) {
		t.Parallel()
		parsed, _ := parseTarget("http://h.test/mcp")
		_, err := buildTarget(parsed, suffix{path: "/a%zz"}, nil)
		var reqErr *requestError
		if !errors.As(err, &reqErr) || reqErr.code != "invalid_target" || reqErr.message != "target URL is not valid after substitution" {
			t.Fatalf("error = %#v", err)
		}
	})

	t.Run("substituted values cannot change the host", func(t *testing.T) {
		t.Parallel()
		parsed, _ := parseTarget("http://h.test/{{a}}")
		u, err := buildTarget(parsed, suffix{}, map[string]string{"a": "@evil.example/"})
		if err != nil {
			t.Fatal(err)
		}
		if u.Host != "h.test" || u.RequestURI() != "/%40evil.example%2F" {
			t.Errorf("got host %q uri %q", u.Host, u.RequestURI())
		}
	})
}

func TestForwardHeaders(t *testing.T) {
	t.Parallel()
	values := map[string]string{"token": "abc", "tenant": "acme corp"}

	t.Run("drops hop-by-hop, control and content-length headers", func(t *testing.T) {
		t.Parallel()
		src := http.Header{
			"Connection":          {"X-Hop"},
			"X-Hop":               {"1"},
			"Keep-Alive":          {"timeout=5"},
			"Transfer-Encoding":   {"chunked"},
			"X-Proxy-Strategy":    {"up"},
			"X-Proxy-Target":      {"http://h"},
			"X-Proxy-Custom":      {"1"},
			"Content-Length":      {"12"},
			"Content-Type":        {"application/json"},
			"Proxy-Authorization": {"Bearer {{token}}"},
			"Authorization":       {"Basic x"},
		}

		got, err := forwardHeaders(src, values)

		if err != nil {
			t.Fatal(err)
		}
		want := http.Header{
			"Content-Type":        {"application/json"},
			"Proxy-Authorization": {"Bearer abc"},
			"Authorization":       {"Basic x"},
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("renders each value and leaves the source untouched", func(t *testing.T) {
		t.Parallel()
		src := http.Header{"X-Multi": {"a-{{tenant}}", "b-{{ token }}", `\{{token}}`}}

		got, err := forwardHeaders(src, values)

		if err != nil {
			t.Fatal(err)
		}
		if want := []string{"a-acme corp", "b-abc", "{{token}}"}; !reflect.DeepEqual(got["X-Multi"], want) {
			t.Errorf("got %q, want %q", got["X-Multi"], want)
		}
		if want := []string{"a-{{tenant}}", "b-{{ token }}", `\{{token}}`}; !reflect.DeepEqual(src["X-Multi"], want) {
			t.Errorf("source was mutated: %q", src["X-Multi"])
		}
	})

	t.Run("rejects unsafe credential values with a command error naming the header", func(t *testing.T) {
		t.Parallel()
		for name, value := range map[string]string{
			"crlf": "a\r\nX-Evil: 1",
			"lf":   "a\nb",
			"cr":   "a\rb",
			"nul":  "a\x00b",
			"del":  "a\x7fb",
		} {
			src := http.Header{"Proxy-Authorization": {"Bearer {{token}}"}}

			_, err := forwardHeaders(src, map[string]string{"token": value})

			var cmdErr *auth.CommandError
			if !errors.As(err, &cmdErr) {
				t.Fatalf("%s: error = %#v, want *auth.CommandError", name, err)
			}
			if want := `a credential value is not valid inside the "proxy-authorization" header`; cmdErr.Message != want {
				t.Errorf("%s: message = %q, want %q", name, cmdErr.Message, want)
			}
			if strings.Contains(cmdErr.Message, "Evil") {
				t.Errorf("%s: message leaks the value", name)
			}
		}
	})

	t.Run("allows tab and non-ASCII bytes", func(t *testing.T) {
		t.Parallel()
		src := http.Header{"X-A": {"{{token}}"}}

		got, err := forwardHeaders(src, map[string]string{"token": "a\tb é"})

		if err != nil || got.Get("X-A") != "a\tb é" {
			t.Fatalf("got %q, %v", got.Get("X-A"), err)
		}
	})

	t.Run("reports an unknown placeholder deterministically", func(t *testing.T) {
		t.Parallel()
		src := http.Header{"B-Header": {"{{b}}"}, "A-Header": {"{{a}}"}}

		_, err := forwardHeaders(src, nil)

		var placeholder *template.PlaceholderError
		if !errors.As(err, &placeholder) || !reflect.DeepEqual(placeholder.Missing, []string{"a"}) {
			t.Fatalf("error = %#v", err)
		}
	})
}

func TestUsesPlaceholders(t *testing.T) {
	t.Parallel()
	plain := targetTemplate{scheme: "http", authority: "h", path: "/p", query: "q=1"}
	cases := []struct {
		name   string
		header http.Header
		target targetTemplate
		want   bool
	}{
		{"nothing", http.Header{"X-A": {"1"}}, plain, false},
		{"header", http.Header{"X-A": {"{{token}}"}}, plain, true},
		{"second value of a header", http.Header{"X-A": {"1", " {{ token }} "}}, plain, true},
		{"path", nil, targetTemplate{path: "/{{token}}"}, true},
		{"query", nil, targetTemplate{query: "a={{token}}"}, true},
		{"control header only", http.Header{"X-Proxy-Note": {"{{token}}"}}, plain, false},
		{"escaped sequence", http.Header{"X-A": {`\{{token}}`}}, plain, false},
		{"malformed braces", http.Header{"X-A": {"{{ }} {{1a}}"}}, plain, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := usesPlaceholders(tc.header, tc.target); got != tc.want {
				t.Errorf("usesPlaceholders = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestHeaderValueJoinsRepeatedValues(t *testing.T) {
	t.Parallel()
	h := http.Header{"X-Proxy-Strategy": {"a", "b"}}
	if got := headerValue(h, "x-proxy-strategy"); got != "a, b" {
		t.Errorf("headerValue = %q", got)
	}
	if got := headerValue(h, "missing"); got != "" {
		t.Errorf("headerValue = %q", got)
	}
}

func TestBracketed(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{"::1": "[::1]", "127.0.0.1": "127.0.0.1", "localhost": "localhost"} {
		if got := bracketed(in); got != want {
			t.Errorf("bracketed(%q) = %q, want %q", in, got, want)
		}
	}
}
