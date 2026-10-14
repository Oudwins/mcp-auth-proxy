package headers

import (
	"net/http"
	"slices"
	"strings"
)

// Proxy-Authorization is deliberately not listed: consumers place credentials there on purpose.
var hopByHop = map[string]bool{
	"connection":         true,
	"keep-alive":         true,
	"proxy-authenticate": true,
	"proxy-connection":   true,
	"te":                 true,
	"trailer":            true,
	"transfer-encoding":  true,
	"upgrade":            true,
}

// IsSafeHeaderValue accepts tab, 0x20-0x7e and 0x80-0xff, judged byte by byte.
func IsSafeHeaderValue(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c != '\t' && c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

func StripHopByHop(h http.Header) http.Header {
	named := map[string]bool{}
	for name, values := range h {
		if !strings.EqualFold(name, "connection") {
			continue
		}
		for _, value := range values {
			for _, token := range strings.Split(value, ",") {
				if token = strings.ToLower(strings.TrimSpace(token)); token != "" {
					named[token] = true
				}
			}
		}
	}
	out := make(http.Header, len(h))
	for name, values := range h {
		lower := strings.ToLower(name)
		if hopByHop[lower] || named[lower] {
			continue
		}
		out[name] = slices.Clone(values)
	}
	return out
}
