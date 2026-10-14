package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/config"
	"github.com/Oudwins/mcp-auth-proxy/internal/logger"
	"github.com/Oudwins/mcp-auth-proxy/internal/proxy"
)

const shutdownTimeout = 5 * time.Second

func runServe(ctx context.Context, cfg *config.Config, log logger.Logger, stderr io.Writer) int {
	running, err := proxy.Start(proxy.Options{Config: cfg, Log: log})
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	log.Info("listening on %s", net.JoinHostPort(running.Host, strconv.Itoa(running.Port)))
	for _, name := range cfg.StrategyNames() {
		log.Info("strategy %s: allowedHosts %s", name, strings.Join(cfg.Strategies[name].AllowedHosts, ", "))
	}

	<-ctx.Done()
	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	if err := running.Close(shutdownCtx); err != nil {
		log.Warn("shutdown did not complete cleanly: %v", err)
	}
	return 0
}
