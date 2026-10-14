package headers

import (
	"net/http"
	"reflect"
	"testing"
)

func TestIsSafeHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{"empty", "", true},
		{"plain ascii", "Bearer abc.def", true},
		{"all printable punctuation", " !\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~", true},
		{"tab", "a\tb", true},
		{"latin-1 byte", "caf\xe9", true},
		{"lowest high byte", "\x80", true},
		{"highest high byte", "\xff", true},
		{"utf-8 encoded text", "café", true},
		{"carriage return", "a\rb", false},
		{"line feed", "a\nb", false},
		{"crlf injection", "ok\r\nX-Evil: 1", false},
		{"nul", "a\x00b", false},
		{"del", "a\x7fb", false},
		{"start of heading", "\x01", false},
		{"vertical tab", "\x0b", false},
		{"form feed", "\x0c", false},
		{"unit separator", "\x1f", false},
		{"trailing newline", "abc\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsSafeHeaderValue(tt.value); got != tt.want {
				t.Errorf("IsSafeHeaderValue(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}

	t.Run("every control byte except tab is rejected", func(t *testing.T) {
		for c := 0; c < 0x20; c++ {
			want := c == '\t'
			if got := IsSafeHeaderValue(string([]byte{byte(c)})); got != want {
				t.Errorf("byte 0x%02x: got %v, want %v", c, got, want)
			}
		}
	})
}

func TestStripHopByHop(t *testing.T) {
	t.Run("removes the hop-by-hop set", func(t *testing.T) {
		in := http.Header{}
		for _, name := range []string{"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Connection", "TE", "Trailer", "Transfer-Encoding", "Upgrade"} {
			in.Set(name, "x")
		}
		in.Set("Content-Type", "text/plain")

		want := http.Header{"Content-Type": {"text/plain"}}
		if got := StripHopByHop(in); !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("keeps Proxy-Authorization", func(t *testing.T) {
		in := http.Header{}
		in.Set("Proxy-Authorization", "Bearer abc")
		got := StripHopByHop(in)
		if got.Get("Proxy-Authorization") != "Bearer abc" {
			t.Errorf("got %v", got)
		}
	})

	t.Run("removes headers named in Connection", func(t *testing.T) {
		in := http.Header{}
		in.Set("Connection", "close, X-Custom ,  x-other")
		in.Set("X-Custom", "1")
		in.Set("X-Other", "2")
		in.Set("X-Kept", "3")

		want := http.Header{"X-Kept": {"3"}}
		if got := StripHopByHop(in); !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("Connection tokens match case-insensitively", func(t *testing.T) {
		in := http.Header{}
		in.Set("Connection", "X-CUSTOM")
		in.Set("x-custom", "1")
		if got := StripHopByHop(in); len(got) != 0 {
			t.Errorf("got %v, want empty", got)
		}
	})

	t.Run("honours every Connection value", func(t *testing.T) {
		in := http.Header{"Connection": {"X-A", "X-B"}, "X-A": {"1"}, "X-B": {"2"}, "X-C": {"3"}}
		want := http.Header{"X-C": {"3"}}
		if got := StripHopByHop(in); !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("Connection can name an end-to-end header", func(t *testing.T) {
		in := http.Header{"Connection": {"Content-Type"}, "Content-Type": {"text/plain"}, "Accept": {"*/*"}}
		want := http.Header{"Accept": {"*/*"}}
		if got := StripHopByHop(in); !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("ignores empty Connection tokens", func(t *testing.T) {
		in := http.Header{"Connection": {" , ,"}, "X-Kept": {"1"}}
		want := http.Header{"X-Kept": {"1"}}
		if got := StripHopByHop(in); !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("keeps canonical keys and multiple values", func(t *testing.T) {
		in := http.Header{}
		in.Add("X-Request-Id", "a")
		in.Add("Set-Cookie", "one=1")
		in.Add("Set-Cookie", "two=2")
		want := http.Header{"X-Request-Id": {"a"}, "Set-Cookie": {"one=1", "two=2"}}
		if got := StripHopByHop(in); !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("non-canonical key for a hop-by-hop header is removed", func(t *testing.T) {
		in := http.Header{"keep-alive": {"timeout=5"}, "connection": {"x-gone"}, "x-gone": {"1"}, "x-kept": {"2"}}
		want := http.Header{"x-kept": {"2"}}
		if got := StripHopByHop(in); !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("nil input returns an empty non-nil header", func(t *testing.T) {
		got := StripHopByHop(nil)
		if got == nil || len(got) != 0 {
			t.Errorf("got %#v", got)
		}
	})

	t.Run("returns a new map and does not mutate the input", func(t *testing.T) {
		in := http.Header{"Connection": {"X-Gone"}, "X-Gone": {"1"}, "X-Kept": {"a"}}
		got := StripHopByHop(in)

		got["X-Kept"][0] = "mutated"
		got.Set("X-New", "1")

		want := http.Header{"Connection": {"X-Gone"}, "X-Gone": {"1"}, "X-Kept": {"a"}}
		if !reflect.DeepEqual(in, want) {
			t.Errorf("input mutated: %v", in)
		}
	})
}
