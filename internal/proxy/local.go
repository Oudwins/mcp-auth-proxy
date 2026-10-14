package proxy

import (
	"context"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Oudwins/mcp-auth-proxy/internal/auth"
)

const (
	localHost         = "stdio.local"
	localShutdownWait = 2 * time.Second
)

type Local struct {
	Client    *http.Client
	URL       string
	Providers map[string]*auth.Provider
	Close     func()
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "pipe" }
func (pipeAddr) String() string  { return localHost }

type pipeListener struct {
	conns chan net.Conn
	done  chan struct{}
	once  sync.Once
}

func newPipeListener() *pipeListener {
	return &pipeListener{conns: make(chan net.Conn), done: make(chan struct{})}
}

func (l *pipeListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.conns:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *pipeListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *pipeListener) Addr() net.Addr { return pipeAddr{} }

func (l *pipeListener) dial(ctx context.Context) (net.Conn, error) {
	client, server := net.Pipe()
	select {
	case l.conns <- server:
		return client, nil
	case <-ctx.Done():
		_ = client.Close()
		_ = server.Close()
		return nil, ctx.Err()
	case <-l.done:
		_ = client.Close()
		_ = server.Close()
		return nil, net.ErrClosed
	}
}

func StartLocal(o Options) (*Local, error) {
	h, providers, upstream, err := newHandler(o)
	if err != nil {
		return nil, err
	}
	h.proxyHosts = map[string]bool{localHost: true}

	listener := newPipeListener()
	server := &http.Server{Handler: h}
	go func() {
		if err := server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			h.log.Error("server stopped unexpectedly: %v", err)
		}
	}()

	transport := &http.Transport{
		Proxy:              nil,
		DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return listener.dial(ctx)
		},
	}

	var closeOnce sync.Once
	closeFn := func() {
		closeOnce.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), localShutdownWait)
			defer cancel()
			if err := server.Shutdown(ctx); err != nil {
				_ = server.Close()
			}
			_ = listener.Close()
			transport.CloseIdleConnections()
			upstream.CloseIdleConnections()
		})
	}

	return &Local{
		Client: &http.Client{
			Transport:     transport,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		URL:       "http://" + localHost + "/",
		Providers: providers,
		Close:     closeFn,
	}, nil
}
