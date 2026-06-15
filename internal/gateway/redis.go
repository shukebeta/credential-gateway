package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"credential-gateway/internal/config"
)

type redisProxy struct {
	cfg      config.RedisService
	log      *slog.Logger
	listener net.Listener
}

func (p *redisProxy) Start() error {
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		return fmt.Errorf("redis proxy: listen %s: %w", p.cfg.Listen, err)
	}
	p.listener = ln
	go p.accept()
	return nil
}

func (p *redisProxy) accept() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *redisProxy) handle(client net.Conn) {
	defer client.Close()
	upstream, err := net.Dial("tcp", p.cfg.Upstream)
	if err != nil {
		p.log.Error("redis proxy: upstream dial failed", "upstream", p.cfg.Upstream, "err", err)
		return
	}
	defer upstream.Close()
	// Inject AUTH before transparent forwarding.
	if p.cfg.Password != "" {
		auth := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(p.cfg.Password), p.cfg.Password)
		if _, err := upstream.Write([]byte(auth)); err != nil {
			p.log.Error("redis proxy: AUTH write failed", "err", err)
			return
		}
		// Drain the +OK response before forwarding client traffic.
		buf := make([]byte, 32)
		if _, err := upstream.Read(buf); err != nil {
			p.log.Error("redis proxy: AUTH read failed", "err", err)
			return
		}
	}
	pipe(client, upstream)
}

func (p *redisProxy) Stop(_ context.Context) error {
	if p.listener == nil {
		return nil
	}
	return p.listener.Close()
}
