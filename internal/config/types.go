package config

import "time"

type Listen struct {
	Host string `zog:"host"`
	Port int    `zog:"port"`
}

// Strategy is a fully resolved strategy. Command is always an argv; a string command from the
// config is stored as {"/bin/sh", "-c", <string>}. AllowedHosts is the effective list (the strategy's
// own list if set, otherwise the global one). Cwd is absolute.
type Strategy struct {
	Command       []string
	Output        string // "token" or "json"
	TTL           time.Duration
	RefreshSkew   time.Duration
	RetryCooldown time.Duration
	Timeout       time.Duration
	RetryOnStatus []int
	AllowedHosts  []string
	Cwd           string
	Env           map[string]string
}

type Config struct {
	Listen       Listen
	LogLevel     string // "info" or "debug"
	MaxBodyBytes int64
	AllowedHosts []string
	Strategies   map[string]Strategy
}
