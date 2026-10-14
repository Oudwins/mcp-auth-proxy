package hosts

import (
	"net/url"
	"strings"
	"testing"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", raw, err)
	}
	return u
}

func allowed(t *testing.T, entries []string, target string) bool {
	t.Helper()
	rules, err := Compile(entries)
	if err != nil {
		t.Fatalf("Compile(%q): %v", entries, err)
	}
	return Allowed(rules, mustURL(t, target))
}

func TestParseRule(t *testing.T) {
	valid := []struct {
		name  string
		entry string
		want  Rule
	}{
		{"defaults to https and 443", "example.com", Rule{"https", "example.com", "443", false}},
		{"defaults to port 80 for http", "http://example.com", Rule{"http", "example.com", "80", false}},
		{"keeps explicit non-default port", "example.com:8443", Rule{"https", "example.com", "8443", false}},
		{"http ip with port", "http://127.0.0.1:1234", Rule{"http", "127.0.0.1", "1234", false}},
		{"lowercases the host", "Example.COM", Rule{"https", "example.com", "443", false}},
		{"trims whitespace", "  example.com  ", Rule{"https", "example.com", "443", false}},
		{"leading wildcard", "*.example.com", Rule{"https", "example.com", "443", true}},
		{"wildcard with scheme and port", "http://*.example.com:8080", Rule{"http", "example.com", "8080", true}},
		{"bracketed ipv6", "[::1]", Rule{"https", "[::1]", "443", false}},
		{"bracketed ipv6 with scheme and port", "http://[::1]:3000", Rule{"http", "[::1]", "3000", false}},
		{"ipv6 is canonicalised", "[0:0:0:0:0:0:0:1]", Rule{"https", "[::1]", "443", false}},
		{"uppercase ipv6 is lowercased", "[2001:DB8::1]", Rule{"https", "[2001:db8::1]", "443", false}},
	}
	for _, tt := range valid {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRule(tt.entry)
			if err != nil {
				t.Fatalf("ParseRule(%q) error: %v", tt.entry, err)
			}
			if got != tt.want {
				t.Errorf("ParseRule(%q) = %+v, want %+v", tt.entry, got, tt.want)
			}
		})
	}

	t.Run("explicit default port equals implicit", func(t *testing.T) {
		for _, pair := range [][2]string{
			{"https://example.com:443", "https://example.com"},
			{"http://example.com:80", "http://example.com"},
		} {
			a, errA := ParseRule(pair[0])
			b, errB := ParseRule(pair[1])
			if errA != nil || errB != nil {
				t.Fatalf("unexpected errors: %v, %v", errA, errB)
			}
			if a != b {
				t.Errorf("ParseRule(%q) = %+v, ParseRule(%q) = %+v", pair[0], a, pair[1], b)
			}
		}
	})

	rejected := []struct{ name, entry string }{
		{"an empty entry", ""},
		{"a blank entry", "   "},
		{"an unsupported scheme", "ftp://example.com"},
		{"a path", "example.com/path"},
		{"a trailing slash", "example.com/"},
		{"userinfo", "user@example.com"},
		{"an inner space", "exa mple.com"},
		{"a dangling port colon", "example.com:"},
		{"a non-numeric port", "example.com:http"},
		{"a bare wildcard", "*"},
		{"a wildcard in the middle", "a.*.example.com"},
		{"a wildcard without a dot", "*example.com"},
	}
	for _, tt := range rejected {
		t.Run("rejects "+tt.name, func(t *testing.T) {
			_, err := ParseRule(tt.entry)
			if err == nil {
				t.Fatalf("ParseRule(%q) should fail", tt.entry)
			}
			if !strings.Contains(err.Error(), `"`+tt.entry+`"`) {
				t.Errorf("error %q should quote the entry %q", err, tt.entry)
			}
		})
	}

	t.Run("rejects a wildcard over a single label", func(t *testing.T) {
		_, err := ParseRule("*.com")
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, want := range []string{"*.com", "too broad"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("error %q should contain %q", err, want)
			}
		}
	})

	t.Run("rejects a wildcard combined with an IP address", func(t *testing.T) {
		for entry, want := range map[string]string{
			"*.[::1]":            "*.[::1]",
			"*.[::ffff:1.2.3.4]": "IP address",
		} {
			_, err := ParseRule(entry)
			if err == nil {
				t.Fatalf("ParseRule(%q) should fail", entry)
			}
			if !strings.Contains(err.Error(), entry) || !strings.Contains(err.Error(), want) {
				t.Errorf("ParseRule(%q) error %q should contain %q", entry, err, want)
			}
		}
	})

	t.Run("rejects an invalid ipv6 literal", func(t *testing.T) {
		for _, entry := range []string{"[:::1]", "[1:2:3]", "[::g]"} {
			if _, err := ParseRule(entry); err == nil {
				t.Errorf("ParseRule(%q) should fail", entry)
			}
		}
	})
}

func TestCompile(t *testing.T) {
	t.Run("compiles each entry in order", func(t *testing.T) {
		rules, err := Compile([]string{"example.com", "http://localhost:3000", "*.example.org"})
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 3 {
			t.Fatalf("len = %d, want 3", len(rules))
		}
		wantHosts := []string{"example.com", "localhost", "example.org"}
		wantWildcards := []bool{false, false, true}
		for i, rule := range rules {
			if rule.Host != wantHosts[i] || rule.Wildcard != wantWildcards[i] {
				t.Errorf("rule %d = %+v, want host %q wildcard %v", i, rule, wantHosts[i], wantWildcards[i])
			}
		}
	})

	t.Run("returns an empty list for no entries", func(t *testing.T) {
		rules, err := Compile([]string{})
		if err != nil {
			t.Fatal(err)
		}
		if len(rules) != 0 {
			t.Errorf("len = %d, want 0", len(rules))
		}
	})

	t.Run("fails if any entry is invalid and names it", func(t *testing.T) {
		_, err := Compile([]string{"example.com", "ftp://bad.example"})
		if err == nil || !strings.Contains(err.Error(), "ftp://bad.example") {
			t.Errorf("error = %v, want one naming ftp://bad.example", err)
		}
	})
}

func TestAllowed(t *testing.T) {
	t.Run("denies everything when there are no rules", func(t *testing.T) {
		if Allowed(nil, mustURL(t, "https://example.com")) {
			t.Error("nil rules should deny")
		}
		if Allowed([]Rule{}, mustURL(t, "https://example.com")) {
			t.Error("empty rules should deny")
		}
	})

	tests := []struct {
		name    string
		entries []string
		target  string
		want    bool
	}{
		{"exact host over https", []string{"example.com"}, "https://example.com/some/path?q=1", true},
		{"different host", []string{"example.com"}, "https://other.com", false},
		{"subdomain of an exact rule", []string{"example.com"}, "https://api.example.com", false},
		{"any rule matches: hit", []string{"a.com", "b.com", "c.com"}, "https://b.com", true},
		{"any rule matches: miss", []string{"a.com", "b.com", "c.com"}, "https://d.com", false},
		{"case-insensitive exact", []string{"Example.COM"}, "https://EXAMPLE.com", true},
		{"case-insensitive wildcard", []string{"*.Example.com"}, "https://API.EXAMPLE.COM", true},

		{"scheme: http denied for a schemeless rule", []string{"example.com"}, "http://example.com", false},
		{"scheme: https denied for an http rule", []string{"http://example.com"}, "https://example.com", false},
		{"scheme: http allowed for an http rule", []string{"http://example.com"}, "http://example.com", true},

		{"port: https and explicit 443", []string{"https://example.com"}, "https://example.com:443", true},
		{"port: rule 443 and implicit target", []string{"https://example.com:443"}, "https://example.com", true},
		{"port: schemeless rule 443", []string{"example.com:443"}, "https://example.com", true},
		{"port: http and explicit 80", []string{"http://example.com"}, "http://example.com:80", true},
		{"port: rule 80 and implicit target", []string{"http://example.com:80"}, "http://example.com", true},
		{"port: mismatch, rule default", []string{"example.com"}, "https://example.com:8443", false},
		{"port: mismatch, target default", []string{"example.com:8443"}, "https://example.com", false},
		{"port: mismatch, both explicit", []string{"example.com:8443"}, "https://example.com:9443", false},
		{"port: exact non-default", []string{"example.com:8443"}, "https://example.com:8443", true},
		{"port: 127.0.0.1:1234 exact", []string{"http://127.0.0.1:1234"}, "http://127.0.0.1:1234", true},
		{"port: 127.0.0.1:1234 wrong scheme", []string{"http://127.0.0.1:1234"}, "https://127.0.0.1:1234", false},
		{"port: 127.0.0.1:1234 default port", []string{"http://127.0.0.1:1234"}, "http://127.0.0.1", false},
		{"port: 127.0.0.1:1234 other port", []string{"http://127.0.0.1:1234"}, "http://127.0.0.1:1235", false},

		{"wildcard: single level", []string{"*.example.com"}, "https://api.example.com", true},
		{"wildcard: two levels", []string{"*.example.com"}, "https://a.b.example.com", true},
		{"wildcard: three levels", []string{"*.example.com"}, "https://a.b.c.example.com", true},
		{"wildcard: not the apex", []string{"*.example.com"}, "https://example.com", false},
		{"wildcard: not a suffix-only match", []string{"*.example.com"}, "https://evilexample.com", false},
		{"wildcard: not a prefix embed", []string{"*.example.com"}, "https://example.com.evil.com", false},
		{"wildcard: not a nested prefix embed", []string{"*.example.com"}, "https://api.example.com.evil.com", false},
		{"wildcard: scheme enforced", []string{"*.example.com"}, "http://api.example.com", false},
		{"wildcard: port enforced", []string{"*.example.com"}, "https://api.example.com:8443", false},
		{"wildcard: http with port allowed", []string{"http://*.example.com:8080"}, "http://api.example.com:8080", true},
		{"wildcard: http with port wrong scheme", []string{"http://*.example.com:8080"}, "https://api.example.com:8080", false},
		{"wildcard: apex rule plus wildcard, apex", []string{"example.com", "*.example.com"}, "https://example.com", true},
		{"wildcard: apex rule plus wildcard, subdomain", []string{"example.com", "*.example.com"}, "https://api.example.com", true},

		{"hostname: ipv4 exact", []string{"http://127.0.0.1:8080"}, "http://127.0.0.1:8080", true},
		{"hostname: ipv4 different", []string{"http://127.0.0.1:8080"}, "http://127.0.0.2:8080", false},
		{"hostname: ipv6 with port", []string{"http://[::1]:3000"}, "http://[::1]:3000", true},
		{"hostname: ipv6 default port", []string{"[::1]"}, "https://[::1]", true},
		{"hostname: different ipv6", []string{"http://[::1]:3000"}, "http://[::2]:3000", false},
		{"hostname: ipv6 different port", []string{"http://[::1]:3000"}, "http://[::1]:3001", false},
		{"hostname: localhost is not 127.0.0.1", []string{"http://localhost:3000"}, "http://127.0.0.1:3000", false},
		{"hostname: 127.0.0.1 is not localhost", []string{"http://127.0.0.1:3000"}, "http://localhost:3000", false},
		{"hostname: userinfo, path, query and fragment ignored", []string{"example.com"}, "https://user:pass@example.com/a/b?c=d#e", true},
		{"hostname: userinfo that looks like an allowed host", []string{"example.com"}, "https://example.com@evil.com", false},
		{"hostname: ftp denied", []string{"example.com"}, "ftp://example.com", false},
		{"hostname: ws denied", []string{"example.com"}, "ws://example.com", false},

		{"ipv6 expanded form in target matches canonical rule", []string{"[::1]"}, "https://[0:0:0:0:0:0:0:1]", true},
		{"ipv6 rule written expanded matches canonical target", []string{"[0:0:0:0:0:0:0:1]"}, "https://[::1]", true},
		{"trailing dot is not equivalent", []string{"example.com"}, "https://example.com.", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allowed(t, tt.entries, tt.target); got != tt.want {
				t.Errorf("Allowed(%q, %q) = %v, want %v", tt.entries, tt.target, got, tt.want)
			}
		})
	}
}
