package template

import (
	"errors"
	"reflect"
	"strings"
	"testing"
)

func placeholderErr(t *testing.T, err error) *PlaceholderError {
	t.Helper()
	var perr *PlaceholderError
	if !errors.As(err, &perr) {
		t.Fatalf("expected *PlaceholderError, got %T: %v", err, err)
	}
	return perr
}

func TestNamePattern(t *testing.T) {
	for _, name := range []string{"a", "A", "_", "_x", "token", "my_token_2", "X1"} {
		t.Run("accepts "+name, func(t *testing.T) {
			if !NamePattern.MatchString(name) {
				t.Errorf("NamePattern should accept %q", name)
			}
		})
	}
	for _, name := range []string{"", "1bad", "a-b", "a b", "a.b", "é", "a\n"} {
		t.Run("rejects "+name, func(t *testing.T) {
			if NamePattern.MatchString(name) {
				t.Errorf("NamePattern should reject %q", name)
			}
		})
	}
}

func TestNames(t *testing.T) {
	tests := []struct {
		name string
		text string
		want []string
	}{
		{"plain text", "plain text", []string{}},
		{"empty", "", []string{}},
		{"single", "Bearer {{token}}", []string{"token"}},
		{"inner spaces", "{{ token }}", []string{"token"}},
		{"inner tab and newline", "{{\ttoken\n}}", []string{"token"}},
		{"asymmetric whitespace", "{{   a}}{{b   }}", []string{"a", "b"}},
		{"js-only whitespace", "{{ a　}}", []string{"a"}},
		{"order with duplicates", "{{b}} {{a}} {{b}} {{a}}", []string{"b", "a", "b", "a"}},
		{"underscores and digits", "{{_x}} {{a_1}} {{A9}}", []string{"_x", "a_1", "A9"}},
		{"escaped is not counted", `\{{token}}`, []string{}},
		{"real next to escaped", `\{{a}} {{b}}`, []string{"b"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Names(tt.text); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Names(%q) = %#v, want %#v", tt.text, got, tt.want)
			}
		})
	}

	for _, text := range []string{"{{1bad}}", "{{a-b}}", "{{}}", "{{ }}", "{ {x} }", "{{x}", "{x}}", "{x}", "{{a b}}", "{{a.b}}"} {
		t.Run("ignores malformed "+text, func(t *testing.T) {
			if got := Names(text); len(got) != 0 {
				t.Errorf("Names(%q) = %#v, want none", text, got)
			}
		})
	}
}

func mustRender(t *testing.T, text string, values map[string]string, encode func(string) string) string {
	t.Helper()
	got, err := Render(text, values, encode)
	if err != nil {
		t.Fatalf("Render(%q) unexpected error: %v", text, err)
	}
	return got
}

func TestRender(t *testing.T) {
	tests := []struct {
		name   string
		text   string
		values map[string]string
		want   string
	}{
		{"no placeholders", "plain text", map[string]string{"a": "1"}, "plain text"},
		{"empty text", "", map[string]string{}, ""},
		{"single", "Bearer {{token}}", map[string]string{"token": "abc"}, "Bearer abc"},
		{"inner whitespace", "{{ token }}", map[string]string{"token": "abc"}, "abc"},
		{"multiple", "{{a}}-{{b}}-{{c}}", map[string]string{"a": "1", "b": "2", "c": "3"}, "1-2-3"},
		{"repeated", "{{a}}/{{a}}/{{ a }}", map[string]string{"a": "x"}, "x/x/x"},
		{"empty value", "a{{x}}b", map[string]string{"x": ""}, "ab"},
		{"malformed 1bad", "{{1bad}}", map[string]string{"x": "X"}, "{{1bad}}"},
		{"malformed a-b", "{{a-b}}", map[string]string{"x": "X"}, "{{a-b}}"},
		{"malformed empty", "{{}}", map[string]string{"x": "X"}, "{{}}"},
		{"malformed spaced braces", "{ {x} }", map[string]string{"x": "X"}, "{ {x} }"},
		{"malformed unclosed", "{{x}", map[string]string{"x": "X"}, "{{x}"},
		{"malformed unknown name", "{{unknown-name}}", map[string]string{}, "{{unknown-name}}"},
		{"nil values with no placeholders", "text", nil, "text"},
		{"multibyte text preserved", "é {{x}} 日本", map[string]string{"x": "1"}, "é 1 日本"},
		{"escape consumes backslash", `\{{token}}`, map[string]string{"token": "abc"}, "{{token}}"},
		{"escape needs no value", `\{{missing}}`, map[string]string{}, "{{missing}}"},
		{"escape only marked occurrence", `\{{a}} and {{a}}`, map[string]string{"a": "1"}, "{{a}} and 1"},
		{"lone escape", `a \{{ b`, map[string]string{}, "a {{ b"},
		{"backslash elsewhere untouched", `a\b {{x}}`, map[string]string{"x": "1"}, `a\b 1`},
		{"value with placeholder not re-expanded", "{{a}}", map[string]string{"a": "{{b}}", "b": "boom"}, "{{b}}"},
		{"self reference not re-expanded", "{{x}}", map[string]string{"x": "{{x}}"}, "{{x}}"},
		{"trailing backslash in value is not an escape", "{{a}}{{b}}", map[string]string{"a": `\`, "b": "1"}, `\1`},
		{"own key named like a prototype member", "{{constructor}}", map[string]string{"constructor": "mine"}, "mine"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustRender(t, tt.text, tt.values, nil); got != tt.want {
				t.Errorf("Render(%q) = %q, want %q", tt.text, got, tt.want)
			}
		})
	}
}

func TestRenderUnknownPlaceholder(t *testing.T) {
	t.Run("reports missing and sorted available", func(t *testing.T) {
		_, err := Render("{{nope}}", map[string]string{"b": "2", "a": "1"}, nil)
		perr := placeholderErr(t, err)
		if !reflect.DeepEqual(perr.Missing, []string{"nope"}) {
			t.Errorf("Missing = %#v", perr.Missing)
		}
		if !reflect.DeepEqual(perr.Available, []string{"a", "b"}) {
			t.Errorf("Available = %#v", perr.Available)
		}
	})

	t.Run("message format", func(t *testing.T) {
		_, err := Render("{{nope}}", map[string]string{"a": "1", "b": "2"}, nil)
		want := "unknown placeholder {{nope}}; this strategy provides: {{a}}, {{b}}"
		if err == nil || err.Error() != want {
			t.Errorf("error = %v, want %q", err, want)
		}
	})

	t.Run("empty available list", func(t *testing.T) {
		_, err := Render("{{nope}}", map[string]string{}, nil)
		perr := placeholderErr(t, err)
		if len(perr.Available) != 0 {
			t.Errorf("Available = %#v, want empty", perr.Available)
		}
		if !reflect.DeepEqual(perr.Missing, []string{"nope"}) {
			t.Errorf("Missing = %#v", perr.Missing)
		}
		if want := "unknown placeholder {{nope}}; this strategy provides: "; err.Error() != want {
			t.Errorf("error = %q, want %q", err.Error(), want)
		}
	})

	t.Run("nil values", func(t *testing.T) {
		_, err := Render("{{nope}}", nil, nil)
		perr := placeholderErr(t, err)
		if len(perr.Available) != 0 {
			t.Errorf("Available = %#v, want empty", perr.Available)
		}
	})

	t.Run("unknown name among known names", func(t *testing.T) {
		_, err := Render("{{a}} {{nope}}", map[string]string{"a": "1"}, nil)
		if perr := placeholderErr(t, err); !reflect.DeepEqual(perr.Missing, []string{"nope"}) {
			t.Errorf("Missing = %#v", perr.Missing)
		}
	})

	t.Run("first unknown name is reported", func(t *testing.T) {
		_, err := Render("{{x}} {{y}}", map[string]string{}, nil)
		if perr := placeholderErr(t, err); !reflect.DeepEqual(perr.Missing, []string{"x"}) {
			t.Errorf("Missing = %#v", perr.Missing)
		}
	})

	t.Run("case sensitive", func(t *testing.T) {
		_, err := Render("{{Token}}", map[string]string{"token": "1"}, nil)
		if perr := placeholderErr(t, err); !reflect.DeepEqual(perr.Missing, []string{"Token"}) {
			t.Errorf("Missing = %#v", perr.Missing)
		}
	})

	for _, name := range []string{"constructor", "__proto__", "toString", "hasOwnProperty", "valueOf"} {
		t.Run("prototype name "+name+" is unknown", func(t *testing.T) {
			_, err := Render("{{"+name+"}}", map[string]string{"a": "1"}, nil)
			perr := placeholderErr(t, err)
			if !reflect.DeepEqual(perr.Missing, []string{name}) {
				t.Errorf("Missing = %#v", perr.Missing)
			}
			if !reflect.DeepEqual(perr.Available, []string{"a"}) {
				t.Errorf("Available = %#v", perr.Available)
			}
		})
	}
}

func TestRenderEncode(t *testing.T) {
	t.Run("defaults to raw values", func(t *testing.T) {
		if got := mustRender(t, "{{x}}", map[string]string{"x": "acme corp/?"}, nil); got != "acme corp/?" {
			t.Errorf("got %q", got)
		}
	})

	tests := []struct {
		name   string
		text   string
		values map[string]string
		want   string
	}{
		{"encodes substituted values", "{{org}}", map[string]string{"org": "acme corp"}, "acme%20corp"},
		{"encodes slashes and question marks", "{{x}}", map[string]string{"x": "a/b?c"}, "a%2Fb%3Fc"},
		{
			"leaves surrounding text alone",
			"https://api.example.com/orgs/{{org}}/items?q=1",
			map[string]string{"org": "acme corp"},
			"https://api.example.com/orgs/acme%20corp/items?q=1",
		},
		{"encodes every substitution", "{{a}}&{{b}}&{{a}}", map[string]string{"a": "1 2", "b": "3 4"}, "1%202&3%204&1%202"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mustRender(t, tt.text, tt.values, EncodeURIComponent); got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}

	t.Run("does not apply encode to the escape", func(t *testing.T) {
		got := mustRender(t, `\{{x}}`, map[string]string{"x": "1"}, func(string) string { return "ENCODED" })
		if got != "{{x}}" {
			t.Errorf("got %q", got)
		}
	})

	t.Run("calls encode with the raw value", func(t *testing.T) {
		var seen []string
		mustRender(t, "{{a}}{{b}}", map[string]string{"a": "x y", "b": "z"}, func(v string) string {
			seen = append(seen, v)
			return v
		})
		if !reflect.DeepEqual(seen, []string{"x y", "z"}) {
			t.Errorf("seen = %#v", seen)
		}
	})

	t.Run("does not call encode without placeholders", func(t *testing.T) {
		calls := 0
		mustRender(t, `plain \{{x}} {{bad-name}}`, map[string]string{}, func(v string) string {
			calls++
			return v
		})
		if calls != 0 {
			t.Errorf("encode called %d times", calls)
		}
	})

	t.Run("does not re-expand encoded output", func(t *testing.T) {
		got := mustRender(t, "{{a}}", map[string]string{"a": "{{b}}", "b": "boom"}, strings.ToUpper)
		if got != "{{B}}" {
			t.Errorf("got %q", got)
		}
	})
}

func TestEncodeURIComponent(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"empty", "", ""},
		{"mixed", "a b/c?d=é&!'()*~", "a%20b%2Fc%3Fd%3D%C3%A9%26!'()*~"},
		{"unreserved punctuation", "-_.!~*'()", "-_.!~*'()"},
		{"alphanumerics", "AZaz09", "AZaz09"},
		{"space is %20 not plus", "a b+c", "a%20b%2Bc"},
		{"reserved gen-delims", ":/?#[]@", "%3A%2F%3F%23%5B%5D%40"},
		{"reserved sub-delims kept and encoded", "$&+,;=", "%24%26%2B%2C%3B%3D"},
		{"percent itself", "100%", "100%25"},
		{"quotes and brackets", "\"<>\\^`{|}", "%22%3C%3E%5C%5E%60%7B%7C%7D"},
		{"control bytes", "\x00\n\r\t\x7f", "%00%0A%0D%09%7F"},
		{"two byte utf-8", "é", "%C3%A9"},
		{"three byte utf-8", "€", "%E2%82%AC"},
		{"cjk", "日本", "%E6%97%A5%E6%9C%AC"},
		{"four byte utf-8", "😀", "%F0%9F%98%80"},
		{"uppercase hex", "\xff", "%FF"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := EncodeURIComponent(tt.in); got != tt.want {
				t.Errorf("EncodeURIComponent(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}

	t.Run("every ascii byte", func(t *testing.T) {
		const unescaped = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
		const hex = "0123456789ABCDEF"
		for c := 0; c < 0x80; c++ {
			got := EncodeURIComponent(string(rune(c)))
			want := "%" + string(hex[c>>4]) + string(hex[c&15])
			if strings.ContainsRune(unescaped, rune(c)) {
				want = string(rune(c))
			}
			if got != want {
				t.Errorf("byte 0x%02x: got %q, want %q", c, got, want)
			}
		}
	})
}
