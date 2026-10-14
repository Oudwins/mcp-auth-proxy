package config

import (
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	z "github.com/Oudwins/zog"
	"github.com/Oudwins/zog/conf"
	"github.com/Oudwins/zog/zconst"
	"go.yaml.in/yaml/v3"

	"github.com/Oudwins/mcp-auth-proxy/internal/hosts"
)

type ConfigError struct{ Message string }

func (e *ConfigError) Error() string { return e.Message }

type rawStrategy struct {
	Command       []string          `zog:"command"`
	Output        string            `zog:"output"`
	TTL           float64           `zog:"ttl"`
	RefreshSkew   float64           `zog:"refreshSkew"`
	RetryCooldown float64           `zog:"retryCooldown"`
	Timeout       float64           `zog:"timeout"`
	RetryOnStatus []int             `zog:"retryOnStatus"`
	AllowedHosts  []string          `zog:"allowedHosts"`
	Cwd           string            `zog:"cwd"`
	Env           map[string]string `zog:"env"`
}

type rawConfig struct {
	Listen       Listen                 `zog:"listen"`
	LogLevel     string                 `zog:"logLevel"`
	MaxBodyBytes int64                  `zog:"maxBodyBytes"`
	AllowedHosts []string               `zog:"allowedHosts"`
	Strategies   map[string]rawStrategy `zog:"strategies"`
}

const (
	defaultHost         = "127.0.0.1"
	defaultPort         = 7600
	defaultMaxBodyBytes = 25 * 1024 * 1024
	maxDurationSeconds  = float64(math.MaxInt64 / int64(time.Second))
)

var (
	strategyName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	durationText = regexp.MustCompile(`^(\d+(?:\.\d+)?)\s*(ms|s|m|h)?$`)
	envReference = regexp.MustCompile(`\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}`)
	unitSeconds  = map[string]float64{"ms": 0.001, "s": 1, "m": 60, "h": 3600}
	configSchema = newConfigSchema()
)

type valueError string

func (e valueError) Error() string { return string(e) }

func describe(value any) string {
	if value == nil {
		return "null"
	}
	switch reflect.TypeOf(value).Kind() {
	case reflect.String:
		return "a string"
	case reflect.Bool:
		return "a boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return "a number"
	case reflect.Map:
		return "a mapping"
	case reflect.Slice, reflect.Array:
		return "a list"
	}
	return fmt.Sprintf("%T", value)
}

func strictString(value any) (any, error) {
	if s, ok := value.(string); ok {
		return s, nil
	}
	return nil, valueError("expected a string, got " + describe(value))
}

func strictList(value any) (any, error) {
	if list, ok := value.([]any); ok {
		return list, nil
	}
	return nil, valueError("expected a list, got " + describe(value))
}

func commandArgv(value any) (any, error) {
	switch v := value.(type) {
	case string:
		if v == "" {
			return nil, valueError("command must not be empty")
		}
		return []any{"/bin/sh", "-c", v}, nil
	case []any:
		return v, nil
	}
	return nil, valueError("expected a string or a list of strings, got " + describe(value))
}

func numberOf(value any) (float64, bool) {
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(rv.Int()), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(rv.Uint()), true
	case reflect.Float32, reflect.Float64:
		return rv.Float(), true
	}
	return 0, false
}

func integerCoercer[T int | int64]() conf.CoercerFunc {
	return func(value any) (any, error) {
		n, ok := numberOf(value)
		if !ok {
			return nil, valueError("expected an integer, got " + describe(value))
		}
		if n != math.Trunc(n) || math.IsInf(n, 0) {
			return nil, valueError(fmt.Sprintf("%v is not an integer", n))
		}
		if n < math.MinInt64 || n >= math.MaxInt64 {
			return nil, valueError(fmt.Sprintf("%v is out of range", n))
		}
		return T(n), nil
	}
}

func durationSeconds(value any) (any, error) {
	if text, ok := value.(string); ok {
		match := durationText.FindStringSubmatch(strings.TrimSpace(text))
		if match == nil {
			return nil, valueError(fmt.Sprintf("%q is not a duration (use e.g. 30s, 55m, 1h)", text))
		}
		amount, err := strconv.ParseFloat(match[1], 64)
		if err != nil {
			return nil, valueError(fmt.Sprintf("%q is not a duration (use e.g. 30s, 55m, 1h)", text))
		}
		unit := match[2]
		if unit == "" {
			unit = "s"
		}
		value = amount * unitSeconds[unit]
	}
	seconds, ok := numberOf(value)
	if !ok {
		return nil, valueError("expected a number of seconds or a duration string, got " + describe(value))
	}
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds > maxDurationSeconds {
		return nil, valueError("duration is out of range")
	}
	return seconds, nil
}

func str() *z.StringSchema[string] {
	return z.String(z.WithCoercer(strictString))
}

func item() *z.StringSchema[string] {
	return str().Required(z.Message("must be a string"))
}

func hostEntry() *z.StringSchema[string] {
	return item().Test(z.Test[*string]{Func: func(entry *string, ctx z.Ctx) {
		if _, err := hosts.ParseRule(*entry); err != nil {
			ctx.AddIssue(ctx.Issue().SetMessage(err.Error()))
		}
	}})
}

func duration(def float64, positive bool) *z.NumberSchema[float64] {
	schema := z.Float64(z.WithCoercer(durationSeconds))
	if positive {
		schema = schema.GT(0, z.Message("must be greater than zero"))
	} else {
		schema = schema.GTE(0, z.Message("must not be negative"))
	}
	return schema.Default(def)
}

func newConfigSchema() *z.StructSchema {
	const hostsHint = "list at least one host"
	port := z.Int(z.WithCoercer(integerCoercer[int]())).
		GTE(0, z.Message("must be an integer between 0 and 65535")).
		LTE(65535, z.Message("must be an integer between 0 and 65535")).
		Default(defaultPort)
	listen := z.Struct(z.Shape{
		"Host": str().Default(defaultHost),
		"Port": port,
	})
	status := z.Int(z.WithCoercer(integerCoercer[int]())).
		Required(z.Message("must be an HTTP status between 100 and 599")).
		GTE(100, z.Message("must be an HTTP status between 100 and 599")).
		LTE(599, z.Message("must be an HTTP status between 100 and 599"))
	strategy := z.Struct(z.Shape{
		"Command": z.Slice(item(), z.WithCoercer(commandArgv)).
			Required(z.Message("command is required")).
			Min(1, z.Message("command must not be empty")),
		"Output": str().
			OneOf([]string{"token", "json"}, z.Message(`must be "token" or "json"`)).
			Default("token"),
		"TTL":           duration(300, true),
		"RefreshSkew":   duration(60, false),
		"RetryCooldown": duration(5, false),
		"Timeout":       duration(30, true),
		"RetryOnStatus": z.Slice(status, z.WithCoercer(strictList)).Default([]int{401}),
		"AllowedHosts": z.Slice(hostEntry(), z.WithCoercer(strictList)).
			Min(1, z.Message(hostsHint)),
		"Cwd": str(),
		"Env": z.EXPERIMENTAL_MAP[string, string](str(), item()),
	})
	return z.Struct(z.Shape{
		"Listen": listen,
		"LogLevel": str().
			OneOf([]string{"info", "debug"}, z.Message(`must be "info" or "debug"`)).
			Default("info"),
		"MaxBodyBytes": z.Int64(z.WithCoercer(integerCoercer[int64]())).
			GT(0, z.Message("must be a positive integer")).
			Default(defaultMaxBodyBytes),
		"AllowedHosts": z.Slice(hostEntry(), z.WithCoercer(strictList)).
			Required(z.Message(hostsHint)).
			Min(1, z.Message(hostsHint)),
		"Strategies": z.EXPERIMENTAL_MAP[string, rawStrategy](
			str().Match(strategyName, z.Message("name must be letters, digits, '.', '_' or '-' and start with a letter or digit")),
			strategy,
		).
			Required(z.Message("at least one strategy is required")).
			Min(1, z.Message("at least one strategy is required")),
	})
}

func formatIssue(e *z.ZogIssue, ctx z.Ctx) {
	if e.Message == "" && e.Code == zconst.IssueCodeCoerce {
		var detail valueError
		if errors.As(e.Err, &detail) {
			e.SetMessage(detail.Error())
			return
		}
		expected := "a value"
		switch e.Dtype {
		case zconst.TypeStruct, zconst.TypeMap:
			expected = "a mapping"
		case zconst.TypeSlice:
			expected = "a list"
		case zconst.TypeString:
			expected = "a string"
		case zconst.TypeNumber:
			expected = "a number"
		}
		e.SetMessage("expected " + expected + ", got " + describe(e.Value))
		return
	}
	conf.DefaultIssueFormatter(e, ctx)
}

func formatPath(path []string) string {
	var out strings.Builder
	for _, segment := range path {
		switch {
		case strings.HasPrefix(segment, `["`) && strings.HasSuffix(segment, `"]`):
			out.WriteString("." + segment[2:len(segment)-2])
		case strings.HasPrefix(segment, "["):
			out.WriteString(segment)
		case out.Len() == 0:
			out.WriteString(segment)
		default:
			out.WriteString("." + segment)
		}
	}
	if out.Len() == 0 {
		return "(root)"
	}
	return out.String()
}

func normalize(value any) any {
	switch v := value.(type) {
	case nil, string, bool:
		return v
	case map[string]any:
		out := make(map[string]any, len(v))
		for key, item := range v {
			out[key] = normalize(item)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = normalize(item)
		}
		return out
	}
	rv := reflect.ValueOf(value)
	switch rv.Kind() {
	case reflect.Map:
		out := make(map[string]any, rv.Len())
		for iter := rv.MapRange(); iter.Next(); {
			out[fmt.Sprint(iter.Key().Interface())] = normalize(iter.Value().Interface())
		}
		return out
	case reflect.Slice, reflect.Array:
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = normalize(rv.Index(i).Interface())
		}
		return out
	}
	return value
}

func interpolateEnv(value any, where string, missing *[]string) any {
	switch v := value.(type) {
	case string:
		return envReference.ReplaceAllStringFunc(v, func(reference string) string {
			name := reference[len("${env:") : len(reference)-1]
			resolved, ok := os.LookupEnv(name)
			if !ok {
				*missing = append(*missing, fmt.Sprintf("%s (at %s)", name, where))
				return ""
			}
			return resolved
		})
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			out[i] = interpolateEnv(item, fmt.Sprintf("%s[%d]", where, i), missing)
		}
		return out
	case map[string]any:
		out := make(map[string]any, len(v))
		for _, key := range slices.Sorted(maps.Keys(v)) {
			out[key] = interpolateEnv(v[key], where+"."+key, missing)
		}
		return out
	}
	return value
}

func zogKey(field reflect.StructField) string {
	key, _, _ := strings.Cut(field.Tag.Get("zog"), ",")
	return key
}

func unknownKeys(value any, typ reflect.Type, path string, found *[]string) {
	child := func(key string) string {
		if path == "" {
			return key
		}
		return path + "." + key
	}
	switch typ.Kind() {
	case reflect.Struct:
		node, ok := value.(map[string]any)
		if !ok {
			return
		}
		fields := map[string]reflect.Type{}
		for i := range typ.NumField() {
			if key := zogKey(typ.Field(i)); key != "" {
				fields[key] = typ.Field(i).Type
			}
		}
		for _, key := range slices.Sorted(maps.Keys(node)) {
			fieldType, known := fields[key]
			if !known {
				*found = append(*found, fmt.Sprintf("  %s: unknown key", child(key)))
				continue
			}
			unknownKeys(node[key], fieldType, child(key), found)
		}
	case reflect.Map:
		node, ok := value.(map[string]any)
		if !ok {
			return
		}
		for _, key := range slices.Sorted(maps.Keys(node)) {
			unknownKeys(node[key], typ.Elem(), child(key), found)
		}
	case reflect.Slice:
		items, ok := value.([]any)
		if !ok {
			return
		}
		for i, item := range items {
			unknownKeys(item, typ.Elem(), fmt.Sprintf("%s[%d]", path, i), found)
		}
	}
}

func invalid(lines []string) *ConfigError {
	slices.Sort(lines)
	lines = slices.Compact(lines)
	return &ConfigError{Message: "invalid config:\n" + strings.Join(lines, "\n")}
}

func Parse(raw any, baseDir string) (*Config, error) {
	tree, ok := normalize(raw).(map[string]any)
	if !ok {
		return nil, invalid([]string{"  (root): expected a mapping of settings, got " + describe(raw)})
	}

	var missing []string
	tree = interpolateEnv(tree, "config", &missing).(map[string]any)
	if len(missing) > 0 {
		return nil, &ConfigError{Message: "environment variables not set: " + strings.Join(missing, ", ")}
	}

	var lines []string
	unknownKeys(tree, reflect.TypeOf(rawConfig{}), "", &lines)
	var parsed rawConfig
	for _, issue := range configSchema.Parse(tree, &parsed, z.WithIssueFormatter(formatIssue)) {
		lines = append(lines, fmt.Sprintf("  %s: %s", formatPath(issue.Path), issue.Message))
	}
	if len(lines) > 0 {
		return nil, invalid(lines)
	}
	return resolve(parsed, baseDir), nil
}

func toDuration(seconds float64) time.Duration {
	return time.Duration(math.Round(seconds * float64(time.Second)))
}

func resolveCwd(baseDir, cwd string) string {
	if cwd == "" {
		cwd = "."
	}
	if !filepath.IsAbs(cwd) {
		cwd = filepath.Join(baseDir, cwd)
	}
	if abs, err := filepath.Abs(cwd); err == nil {
		return abs
	}
	return filepath.Clean(cwd)
}

func resolve(raw rawConfig, baseDir string) *Config {
	strategies := make(map[string]Strategy, len(raw.Strategies))
	for name, s := range raw.Strategies {
		allowed := s.AllowedHosts
		if allowed == nil {
			allowed = raw.AllowedHosts
		}
		env := s.Env
		if env == nil {
			env = map[string]string{}
		}
		strategies[name] = Strategy{
			Command:       s.Command,
			Output:        s.Output,
			TTL:           toDuration(s.TTL),
			RefreshSkew:   toDuration(s.RefreshSkew),
			RetryCooldown: toDuration(s.RetryCooldown),
			Timeout:       toDuration(s.Timeout),
			RetryOnStatus: s.RetryOnStatus,
			AllowedHosts:  allowed,
			Cwd:           resolveCwd(baseDir, s.Cwd),
			Env:           env,
		}
	}
	return &Config{
		Listen:       raw.Listen,
		LogLevel:     raw.LogLevel,
		MaxBodyBytes: raw.MaxBodyBytes,
		AllowedHosts: raw.AllowedHosts,
		Strategies:   strategies,
	}
}

func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "mcp-auth-proxy", "config.yaml")
}

func Load(path string) (*Config, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		absolute = path
	}
	data, err := os.ReadFile(absolute)
	if err != nil {
		return nil, &ConfigError{Message: fmt.Sprintf("cannot read config at %s: %v", absolute, err)}
	}
	var raw any
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, &ConfigError{Message: fmt.Sprintf("config at %s is not valid YAML: %v", absolute, err)}
	}
	return Parse(raw, filepath.Dir(absolute))
}

func (c *Config) StrategyNames() []string {
	return slices.Sorted(maps.Keys(c.Strategies))
}
