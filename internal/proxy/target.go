package proxy

import (
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"

	"github.com/Oudwins/mcp-auth-proxy/internal/auth"
	"github.com/Oudwins/mcp-auth-proxy/internal/headers"
	"github.com/Oudwins/mcp-auth-proxy/internal/template"
)

const (
	strategyHeader      = "X-Proxy-Strategy"
	targetHeader        = "X-Proxy-Target"
	controlHeaderPrefix = "x-proxy-"
)

var (
	targetPattern    = regexp.MustCompile(`^([Hh][Tt][Tt][Pp][Ss]?)://([^/?#]*)([^?#]*)(?:\?([^#]*))?$`)
	authorityPattern = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?|\[[0-9A-Fa-f:.]+\])(?::\d{1,5})?$`)
)

type requestError struct {
	status  int
	code    string
	message string
}

func (e *requestError) Error() string { return e.message }

func invalidTarget(message string) error {
	return &requestError{status: http.StatusBadRequest, code: "invalid_target", message: message}
}

type targetTemplate struct {
	scheme    string
	authority string
	path      string
	query     string
}

func parseTarget(raw string) (targetTemplate, error) {
	match := targetPattern.FindStringSubmatch(strings.TrimSpace(raw))
	if match == nil {
		return targetTemplate{}, invalidTarget(strings.ToLower(targetHeader) + " must be an absolute http(s) URL without a fragment")
	}
	authority := match[2]
	if strings.Contains(authority, "{{") {
		return targetTemplate{}, invalidTarget("placeholders are not allowed in the scheme or host of the target")
	}
	if !authorityPattern.MatchString(authority) {
		return targetTemplate{}, invalidTarget(fmt.Sprintf("%q is not a valid host[:port]", authority))
	}
	return targetTemplate{scheme: strings.ToLower(match[1]), authority: authority, path: match[3], query: match[4]}, nil
}

func (t targetTemplate) originURL() (*url.URL, error) {
	u, err := url.Parse(t.scheme + "://" + t.authority + "/")
	if err != nil {
		return nil, invalidTarget(fmt.Sprintf("%q is not a valid host[:port]", t.authority))
	}
	return u, nil
}

// suffix is the already-escaped path and raw query of the incoming request.
type suffix struct {
	path  string
	query string
}

func buildTarget(t targetTemplate, s suffix, values map[string]string) (*url.URL, error) {
	path, err := template.Render(t.path, values, template.EncodeURIComponent)
	if err != nil {
		return nil, err
	}
	if s.path != "" {
		path = strings.TrimRight(path, "/") + s.path
	}
	query, err := template.Render(t.query, values, template.EncodeURIComponent)
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, part := range []string{query, s.query} {
		if part != "" {
			parts = append(parts, part)
		}
	}

	full := t.scheme + "://" + t.authority + escapeBytes(path, pathAllowed)
	if len(parts) > 0 {
		full += "?" + escapeBytes(strings.Join(parts, "&"), queryAllowed)
	}
	target, err := url.Parse(full)
	if err != nil {
		return nil, invalidTarget("target URL is not valid after substitution")
	}
	origin, err := t.originURL()
	if err != nil {
		return nil, err
	}
	if !strings.EqualFold(target.Host, origin.Host) {
		return nil, invalidTarget("target host changed during substitution")
	}
	target.Host = outgoingHost(target)
	return target, nil
}

// outgoingHost lowercases the host and drops a port that is the scheme default.
func outgoingHost(u *url.URL) string {
	port := u.Port()
	if port == "80" && u.Scheme == "http" || port == "443" && u.Scheme == "https" {
		host := strings.ToLower(u.Hostname())
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return strings.ToLower(u.Host)
}

const hexDigits = "0123456789ABCDEF"

// Paths use an allowlist so that url.Parse keeps RawPath valid and an encoded %2F never turns into "/".
func pathAllowed(c byte) bool {
	switch {
	case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		return true
	}
	return strings.IndexByte("-._~!$&'()*+,;=:@[]%/", c) >= 0
}

// Mirrors the WHATWG special-scheme query percent-encode set so that nothing breaks the request line.
func queryAllowed(c byte) bool {
	return c > 0x20 && c < 0x7f && !strings.ContainsRune(`"#<>'`, rune(c))
}

func escapeBytes(s string, allowed func(byte) bool) string {
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if allowed(c) {
			out.WriteByte(c)
			continue
		}
		out.WriteByte('%')
		out.WriteByte(hexDigits[c>>4])
		out.WriteByte(hexDigits[c&0x0f])
	}
	return out.String()
}

func headerValue(h http.Header, name string) string {
	return strings.Join(h.Values(name), ", ")
}

func isControlHeader(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), controlHeaderPrefix)
}

func usesPlaceholders(h http.Header, t targetTemplate) bool {
	if len(template.Names(t.path)) > 0 || len(template.Names(t.query)) > 0 {
		return true
	}
	for name, values := range h {
		if isControlHeader(name) {
			continue
		}
		for _, value := range values {
			if len(template.Names(value)) > 0 {
				return true
			}
		}
	}
	return false
}

func forwardHeaders(src http.Header, values map[string]string) (http.Header, error) {
	out := headers.StripHopByHop(src)
	for name := range out {
		if isControlHeader(name) || strings.EqualFold(name, "Content-Length") {
			delete(out, name)
		}
	}
	for _, name := range slices.Sorted(maps.Keys(out)) {
		items := out[name]
		for i, item := range items {
			rendered, err := template.Render(item, values, nil)
			if err != nil {
				return nil, err
			}
			if !headers.IsSafeHeaderValue(rendered) {
				return nil, &auth.CommandError{
					Message: fmt.Sprintf("a credential value is not valid inside the %q header", strings.ToLower(name)),
				}
			}
			items[i] = rendered
		}
	}
	return out, nil
}
