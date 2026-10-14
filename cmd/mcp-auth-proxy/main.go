package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"math"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/auth"
	"github.com/Oudwins/mcp-auth-proxy/internal/config"
	"github.com/Oudwins/mcp-auth-proxy/internal/logger"
)

var version = "dev"

const configEnv = "MCP_AUTH_PROXY_CONFIG"

func usage() string {
	return `mcp-auth-proxy: local reverse proxy that injects generated credentials into requests to remote MCP servers

Usage:
  mcp-auth-proxy [serve] [options]      start the proxy (default)
  mcp-auth-proxy check [strategy...]    run the auth command(s) once and show what they return

Options:
  -c, --config <path>   config file (default: $` + configEnv + ` or ` + config.DefaultPath() + `)
  -p, --port <number>   override listen.port
      --host <address>  override listen.host
      --debug           log every proxied request
  -h, --help            show this help
  -v, --version         show the version
`
}

type options struct {
	config      *string
	port        *string
	host        *string
	debug       bool
	help        bool
	version     bool
	positionals []string
}

type optionSpec struct {
	takesValue bool
	set        func(o *options, value string)
}

var longOptions = map[string]optionSpec{
	"config":  {true, func(o *options, v string) { o.config = &v }},
	"port":    {true, func(o *options, v string) { o.port = &v }},
	"host":    {true, func(o *options, v string) { o.host = &v }},
	"debug":   {false, func(o *options, _ string) { o.debug = true }},
	"help":    {false, func(o *options, _ string) { o.help = true }},
	"version": {false, func(o *options, _ string) { o.version = true }},
}

var shortOptions = map[byte]string{'c': "config", 'p': "port", 'h': "help", 'v': "version"}

func parseArgs(args []string) (options, error) {
	var o options
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--":
			o.positionals = append(o.positionals, args[i+1:]...)
			return o, nil
		case strings.HasPrefix(arg, "--"):
			name, value, hasValue := strings.Cut(arg[2:], "=")
			spec, ok := longOptions[name]
			if !ok {
				return o, fmt.Errorf("unknown option %q", "--"+name)
			}
			switch {
			case !spec.takesValue && hasValue:
				return o, fmt.Errorf("option %q does not take a value", "--"+name)
			case spec.takesValue && !hasValue:
				if i+1 >= len(args) {
					return o, fmt.Errorf("option %q requires a value", "--"+name)
				}
				i++
				value = args[i]
			}
			spec.set(&o, value)
		case len(arg) > 1 && arg[0] == '-':
			for j := 1; j < len(arg); j++ {
				name, ok := shortOptions[arg[j]]
				if !ok {
					return o, fmt.Errorf("unknown option %q", "-"+string(arg[j]))
				}
				spec := longOptions[name]
				if !spec.takesValue {
					spec.set(&o, "")
					continue
				}
				value := arg[j+1:]
				if value == "" {
					if i+1 >= len(args) {
						return o, fmt.Errorf("option %q requires a value", "-"+string(arg[j]))
					}
					i++
					value = args[i]
				}
				spec.set(&o, value)
				break
			}
		default:
			o.positionals = append(o.positionals, arg)
		}
	}
	return o, nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr, os.Getenv)
	stop()
	os.Exit(code)
}

func usageFailure(stderr io.Writer, message string) int {
	fmt.Fprintf(stderr, "%s\n\n%s", message, usage())
	return 2
}

func failure(stderr io.Writer, err error) int {
	var configErr *config.ConfigError
	if errors.As(err, &configErr) {
		fmt.Fprintf(stderr, "config error: %s\n", configErr.Message)
		return 2
	}
	fmt.Fprintf(stderr, "error: %v\n", err)
	return 1
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer, env func(string) string) int {
	opts, err := parseArgs(args)
	if err != nil {
		return usageFailure(stderr, "error: "+err.Error())
	}
	if opts.help {
		io.WriteString(stdout, usage())
		return 0
	}
	if opts.version {
		fmt.Fprintln(stdout, version)
		return 0
	}

	command, rest := "serve", opts.positionals
	if len(rest) > 0 {
		command, rest = rest[0], rest[1:]
	}
	switch {
	case command != "serve" && command != "check":
		return usageFailure(stderr, fmt.Sprintf("unknown command %q", command))
	case command == "serve" && len(rest) > 0:
		return usageFailure(stderr, fmt.Sprintf("unexpected argument %q for serve", rest[0]))
	}

	path := config.DefaultPath()
	if opts.config != nil {
		path = *opts.config
	} else if fromEnv := env(configEnv); fromEnv != "" {
		path = fromEnv
	}
	cfg, err := config.Load(path)
	if err != nil {
		return failure(stderr, err)
	}
	if opts.port != nil {
		port, err := strconv.Atoi(*opts.port)
		if err != nil || port < 0 || port > math.MaxUint16 {
			return failure(stderr, &config.ConfigError{Message: fmt.Sprintf("invalid --port %q", *opts.port)})
		}
		cfg.Listen.Port = port
	}
	if opts.host != nil {
		cfg.Listen.Host = *opts.host
	}

	log := logger.New(opts.debug || cfg.LogLevel == "debug", stderr)
	if command == "check" {
		return runCheck(ctx, cfg, rest, log, stdout, stderr)
	}
	return runServe(ctx, cfg, log, stderr)
}

func mask(value string) string {
	runes := []rune(value)
	shown := ""
	if len(runes) >= 24 {
		shown = string(runes[:6]) + "... "
	}
	return fmt.Sprintf("%s(%d chars)", shown, len(runes))
}

func describeDuration(d time.Duration) string {
	minutes := math.Floor(d.Minutes() + 0.5)
	switch {
	case minutes >= 120:
		return fmt.Sprintf("%dh", int(math.Floor(minutes/60+0.5)))
	case minutes >= 1:
		return fmt.Sprintf("%dm", int(minutes))
	}
	return fmt.Sprintf("%ds", int(math.Floor(d.Seconds()+0.5)))
}

func runCheck(ctx context.Context, cfg *config.Config, requested []string, log logger.Logger, stdout, stderr io.Writer) int {
	var unknown []string
	for _, name := range requested {
		if _, ok := cfg.Strategies[name]; !ok {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		return failure(stderr, &config.ConfigError{Message: fmt.Sprintf(
			"unknown strategy(ies): %s (available: %s)", strings.Join(unknown, ", "), strings.Join(cfg.StrategyNames(), ", "))})
	}
	names := requested
	if len(names) == 0 {
		names = cfg.StrategyNames()
	}

	failures := 0
	for _, name := range names {
		strategy := cfg.Strategies[name]
		provider := auth.NewProvider(auth.ProviderOptions{Name: name, Strategy: strategy, Log: log})
		creds, err := provider.Get(ctx)
		if err != nil {
			failures++
			fmt.Fprintf(stdout, "%s: FAILED\n  %s\n", name, logger.Redact(err.Error()))
			continue
		}
		fmt.Fprintf(stdout, "%s: ok\n", name)
		for _, key := range slices.Sorted(maps.Keys(creds.Values)) {
			fmt.Fprintf(stdout, "  {{%s}}: %s\n", key, mask(creds.Values[key]))
		}
		fmt.Fprintf(stdout, "  expires: %s (in %s, from %s)\n",
			creds.ExpiresAt.UTC().Format("2006-01-02T15:04:05.000Z"), describeDuration(time.Until(creds.ExpiresAt)), creds.ExpirySource)
		fmt.Fprintf(stdout, "  allowedHosts: %s\n", strings.Join(strategy.AllowedHosts, ", "))
	}
	if failures > 0 {
		return 1
	}
	return 0
}
