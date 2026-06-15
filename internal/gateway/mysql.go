package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"net"

	"credential-gateway/internal/config"
)

type mysqlProxy struct {
	cfg      config.MySQLService
	log      *slog.Logger
	listener net.Listener
}

func (p *mysqlProxy) Start() error {
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		return fmt.Errorf("mysql proxy: listen %s: %w", p.cfg.Listen, err)
	}
	p.listener = ln
	go p.accept()
	return nil
}

func (p *mysqlProxy) accept() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *mysqlProxy) handle(client net.Conn) {
	defer client.Close()
	upstream, err := net.Dial("tcp", p.cfg.Upstream)
	if err != nil {
		p.log.Error("mysql proxy: upstream dial failed", "upstream", p.cfg.Upstream, "err", err)
		return
	}
	defer upstream.Close()
	pipe(client, upstream)
}

func (p *mysqlProxy) Stop(_ context.Context) error {
	if p.listener == nil {
		return nil
	}
	return p.listener.Close()
}
