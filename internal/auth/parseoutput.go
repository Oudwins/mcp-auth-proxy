package auth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	msMistakeThresholdMs = 400 * 24 * 60 * 60 * 1000
	maxDateMs            = 8.64e15
)

var valueName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type Parsed struct {
	Values       map[string]string
	ExpiresAt    time.Time
	ExpirySource string
}

type outputBody struct {
	values           map[string]string
	expiresAt        any
	expiresInSeconds float64
	hasInSeconds     bool
}

// isJSSpace matches the characters JavaScript's trim() and \s treat as whitespace.
func isJSSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
		return true
	}
	return r >= 0x2000 && r <= 0x200a
}

func trimJS(s string) string {
	return strings.TrimFunc(s, isJSSpace)
}

func hasControlChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func msToTime(ms float64) time.Time {
	return time.UnixMilli(int64(math.Max(-maxDateMs, math.Min(maxDateMs, ms)))).UTC()
}

func jwtExpiryMs(value string) (float64, bool) {
	parts := strings.FieldsFunc(value, isJSSpace)
	if len(parts) == 0 {
		return 0, false
	}
	segments := strings.Split(parts[len(parts)-1], ".")
	if len(segments) != 3 {
		return 0, false
	}
	encoded := strings.NewReplacer("+", "-", "/", "_").Replace(strings.TrimRight(segments[1], "="))
	payload, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return 0, false
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return 0, false
	}
	exp, ok := claims["exp"].(float64)
	if !ok {
		return 0, false
	}
	return exp * 1000, true
}

func parseTimestamp(s string) (time.Time, bool) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, true
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, true
	}
	for _, layout := range []string{"2006-01-02T15:04:05", "2006-01-02T15:04"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func decodeJSONOutput(text string) (outputBody, error) {
	notJSON := commandErrorf(`auth command output is not valid JSON; expected {"values": {...}} (for a bare token use output "token")`)
	dec := json.NewDecoder(strings.NewReader(text))
	dec.UseNumber()
	var doc any
	if err := dec.Decode(&doc); err != nil {
		return outputBody{}, notJSON
	}
	if _, err := dec.Token(); err != io.EOF {
		return outputBody{}, notJSON
	}

	var body outputBody
	var issues []string
	obj, ok := doc.(map[string]any)
	if !ok {
		issues = append(issues, "(root): expected object")
		obj = nil
	}

	if raw, present := obj["values"]; !present {
		if ok {
			issues = append(issues, "values: required")
		}
	} else if m, isMap := raw.(map[string]any); !isMap {
		issues = append(issues, "values: expected object")
	} else {
		body.values = make(map[string]string, len(m))
		for _, name := range sortedKeys(m) {
			if s, isString := m[name].(string); isString {
				body.values[name] = s
			} else {
				issues = append(issues, fmt.Sprintf("values.%s: expected string", name))
			}
		}
	}

	if raw, present := obj["expiresAt"]; present {
		switch v := raw.(type) {
		case json.Number:
			if f, err := v.Float64(); err == nil {
				body.expiresAt = f
			} else {
				issues = append(issues, "expiresAt: expected a finite number")
			}
		case string:
			body.expiresAt = v
		default:
			issues = append(issues, "expiresAt: expected number or string")
		}
	}

	if raw, present := obj["expiresInSeconds"]; present {
		n, isNumber := raw.(json.Number)
		f, err := n.Float64()
		switch {
		case !isNumber || err != nil:
			issues = append(issues, "expiresInSeconds: expected number")
		case f <= 0:
			issues = append(issues, "expiresInSeconds: must be greater than 0")
		default:
			body.expiresInSeconds, body.hasInSeconds = f, true
		}
	}

	for _, key := range sortedKeys(obj) {
		if key != "values" && key != "expiresAt" && key != "expiresInSeconds" {
			issues = append(issues, fmt.Sprintf("%s: unrecognized key", key))
		}
	}

	if len(issues) > 0 {
		return outputBody{}, commandErrorf("auth command output has the wrong shape (%s)", strings.Join(issues, "; "))
	}
	return body, nil
}

func (b outputBody) explicitExpiryMs(nowMs float64) (float64, bool, error) {
	switch v := b.expiresAt.(type) {
	case float64:
		ms := v * 1000
		if ms > nowMs+msMistakeThresholdMs {
			return 0, false, commandErrorf("expiresAt is too far in the future; it must be epoch seconds, not milliseconds")
		}
		return ms, true, nil
	case string:
		t, ok := parseTimestamp(v)
		if !ok {
			return 0, false, commandErrorf("expiresAt is not a valid ISO 8601 timestamp")
		}
		return float64(t.UnixMilli()), true, nil
	}
	if b.hasInSeconds {
		return nowMs + b.expiresInSeconds*1000, true, nil
	}
	return 0, false, nil
}

func validateValues(values map[string]string) error {
	if len(values) == 0 {
		return commandErrorf("auth command returned no values")
	}
	for _, name := range sortedKeys(values) {
		value := values[name]
		switch {
		case !valueName.MatchString(name):
			return commandErrorf(`auth command returned invalid value name "%s" (use letters, digits and _)`, name)
		case value == "":
			return commandErrorf(`auth command returned an empty value for "%s"`, name)
		case hasControlChars(value):
			return commandErrorf(`auth command returned a value for "%s" containing control characters`, name)
		}
	}
	return nil
}

// ParseOutput validates the command's stdout for the given output mode ("token" or "json") and decides
// when the credentials expire.
func ParseOutput(stdout string, output string, ttl time.Duration, now time.Time) (Parsed, error) {
	text := trimJS(strings.ToValidUTF8(stdout, "\ufffd"))
	if text == "" {
		return Parsed{}, commandErrorf("auth command printed nothing to stdout")
	}
	nowMs := float64(now.UnixMilli())

	var values map[string]string
	var explicitMs float64
	var hasExplicit bool
	if output == "token" {
		if strings.IndexFunc(text, isJSSpace) >= 0 {
			return Parsed{}, commandErrorf(`auth command output is not a single token (use output "json" for JSON output)`)
		}
		values = map[string]string{"token": text}
	} else {
		body, err := decodeJSONOutput(text)
		if err != nil {
			return Parsed{}, err
		}
		values = body.values
		if explicitMs, hasExplicit, err = body.explicitExpiryMs(nowMs); err != nil {
			return Parsed{}, err
		}
	}

	if err := validateValues(values); err != nil {
		return Parsed{}, err
	}

	var expiresMs float64
	var source string
	if hasExplicit {
		expiresMs, source = explicitMs, "output"
	} else {
		earliest, found := math.Inf(1), false
		for _, value := range values {
			if exp, ok := jwtExpiryMs(value); ok {
				earliest, found = math.Min(earliest, exp), true
			}
		}
		if found {
			expiresMs, source = earliest, "jwt"
		} else {
			expiresMs, source = nowMs+float64(ttl.Milliseconds()), "ttl"
		}
	}
	if expiresMs <= nowMs {
		return Parsed{}, commandErrorf("auth command returned credentials that are already expired")
	}

	return Parsed{Values: values, ExpiresAt: msToTime(expiresMs), ExpirySource: source}, nil
}
