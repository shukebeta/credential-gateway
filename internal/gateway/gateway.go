package gateway

import (
	"context"
	"log/slog"
	"sync"

	"credential-gateway/internal/config"
)

// Listener is the common interface for all protocol proxies.
type Listener interface {
	Start() error
	Stop(ctx context.Context) error
}

// Gateway holds all active listeners and coordinates their lifecycle.
type Gateway struct {
	listeners []namedListener
	log       *slog.Logger
}

type namedListener struct {
	name string
	l    Listener
}

func New(cfg *config.Config, log *slog.Logger) *Gateway {
	g := &Gateway{log: log}
	for _, h := range cfg.HTTP {
		g.listeners = append(g.listeners, namedListener{
			name: "http:" + h.Listen,
			l:    &httpProxy{cfg: h, log: log},
		})
	}
	for _, m := range cfg.MySQL {
		g.listeners = append(g.listeners, namedListener{
			name: "mysql:" + m.Listen,
			l:    &mysqlProxy{cfg: m, log: log},
		})
	}
	for _, r := range cfg.Redis {
		g.listeners = append(g.listeners, namedListener{
			name: "redis:" + r.Listen,
			l:    &redisProxy{cfg: r, log: log},
		})
	}
	return g
}

func (g *Gateway) Start() error {
	for _, nl := range g.listeners {
		if err := nl.l.Start(); err != nil {
			return err
		}
		g.log.Info("listening", "addr", nl.name)
	}
	return nil
}

func (g *Gateway) Stop(ctx context.Context) {
	var wg sync.WaitGroup
	for _, nl := range g.listeners {
		wg.Add(1)
		go func(nl namedListener) {
			defer wg.Done()
			if err := nl.l.Stop(ctx); err != nil {
				g.log.Warn("stop error", "addr", nl.name, "err", err)
			}
		}(nl)
	}
	wg.Wait()
}
