package template

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

type PlaceholderError struct {
	Missing   []string
	Available []string
}

func (e *PlaceholderError) Error() string {
	return fmt.Sprintf("unknown placeholder %s; this strategy provides: %s", braced(e.Missing), braced(e.Available))
}

func braced(names []string) string {
	wrapped := make([]string, len(names))
	for i, name := range names {
		wrapped[i] = "{{" + name + "}}"
	}
	return strings.Join(wrapped, ", ")
}

var NamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ws spells out JavaScript's \s, which is wider than RE2's ASCII-only \s.
const ws = `[\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}]*`

// `\{{` is the escape for a literal `{{`.
var token = regexp.MustCompile(`\\\{\{|\{\{` + ws + `([A-Za-z_][A-Za-z0-9_]*)` + ws + `\}\}`)

func Names(text string) []string {
	names := []string{}
	for _, match := range token.FindAllStringSubmatchIndex(text, -1) {
		if match[2] >= 0 {
			names = append(names, text[match[2]:match[3]])
		}
	}
	return names
}

func Render(text string, values map[string]string, encode func(string) string) (string, error) {
	if encode == nil {
		encode = func(value string) string { return value }
	}
	var out strings.Builder
	last := 0
	for _, match := range token.FindAllStringSubmatchIndex(text, -1) {
		out.WriteString(text[last:match[0]])
		last = match[1]
		if match[2] < 0 {
			out.WriteString("{{")
			continue
		}
		name := text[match[2]:match[3]]
		value, ok := values[name]
		if !ok {
			return "", &PlaceholderError{Missing: []string{name}, Available: slices.Sorted(maps.Keys(values))}
		}
		out.WriteString(encode(value))
	}
	out.WriteString(text[last:])
	return out.String(), nil
}

// EncodeURIComponent mirrors JavaScript's encodeURIComponent, operating on UTF-8 bytes.
func EncodeURIComponent(s string) string {
	const hex = "0123456789ABCDEF"
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnescaped(c) {
			out.WriteByte(c)
			continue
		}
		out.WriteByte('%')
		out.WriteByte(hex[c>>4])
		out.WriteByte(hex[c&0x0f])
	}
	return out.String()
}

func isUnescaped(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-_.!~*'()", c) >= 0
}
