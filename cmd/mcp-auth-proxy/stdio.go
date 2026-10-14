package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/Oudwins/mcp-auth-proxy/internal/bridge"
	"github.com/Oudwins/mcp-auth-proxy/internal/config"
	"github.com/Oudwins/mcp-auth-proxy/internal/logger"
	"github.com/Oudwins/mcp-auth-proxy/internal/proxy"
)

const reservedHeaderPrefix = "x-proxy-"

var envReference = regexp.MustCompile(`\$\{env:([A-Za-z_][A-Za-z0-9_]*)\}`)

type headerLine struct {
	name  string
	value string
}

func parseHeaderLine(line string) (headerLine, error) {
	name, value, ok := strings.Cut(line, ":")
	if !ok {
		return headerLine{}, fmt.Errorf("invalid header %q: expected \"Name: value\"", line)
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return headerLine{}, fmt.Errorf("invalid header %q: empty header name", line)
	}
	if strings.ContainsFunc(name, func(r rune) bool { return r <= ' ' || r >= 0x7f || strings.ContainsRune("()<>@,;:\\\"/[]?={}", r) }) {
		return headerLine{}, fmt.Errorf("invalid header %q: bad header name", line)
	}
	if strings.HasPrefix(strings.ToLower(name), reservedHeaderPrefix) {
		return headerLine{}, fmt.Errorf("header %q is reserved (names starting with X-Proxy- are set by mcp-auth-proxy)", name)
	}
	return headerLine{name: name, value: strings.TrimSpace(value)}, nil
}

func parseHeaderLines(lines []string) ([]headerLine, error) {
	parsed := make([]headerLine, 0, len(lines))
	for _, line := range lines {
		h, err := parseHeaderLine(line)
		if err != nil {
			return nil, err
		}
		parsed = append(parsed, h)
	}
	return parsed, nil
}

func buildHeaders(lines []headerLine, env func(string) string) (http.Header, error) {
	headers := http.Header{}
	for _, line := range lines {
		var missing []string
		value := envReference.ReplaceAllStringFunc(line.value, func(ref string) string {
			name := envReference.FindStringSubmatch(ref)[1]
			got := env(name)
			if got == "" {
				missing = append(missing, name)
			}
			return got
		})
		if len(missing) > 0 {
			return nil, &config.ConfigError{Message: fmt.Sprintf(
				"header %q references environment variable(s) that are not set or empty: %s", line.name, strings.Join(missing, ", "))}
		}
		if strings.ContainsAny(value, "\r\n") {
			return nil, &config.ConfigError{Message: fmt.Sprintf("header %q contains a line break", line.name)}
		}
		headers.Add(line.name, value)
	}
	return headers, nil
}

type stdioParams struct {
	strategy string
	target   string
	headers  http.Header
}

func runStdio(ctx context.Context, cfg *config.Config, p stdioParams, log logger.Logger, stdin io.Reader, stdout, stderr io.Writer) int {
	local, err := proxy.StartLocal(proxy.Options{Config: cfg, Log: log})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	defer local.Close()

	err = bridge.Run(ctx, bridge.Options{
		Client:   local.Client,
		URL:      local.URL,
		Strategy: p.strategy,
		Target:   p.target,
		Headers:  p.headers,
		In:       stdin,
		Out:      stdout,
		Log:      log,
	})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	return 0
}
