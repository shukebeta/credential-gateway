package gateway

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"

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

	// Wrap client in a buffered reader so we can peek for AUTH without consuming it.
	br := bufio.NewReader(client)
	if err := discardClientAuth(br, client); err != nil {
		p.log.Error("redis proxy: client AUTH intercept failed", "err", err)
		return
	}

	// Drain bytes buffered by the peek/read phase; prepend them to the pipe
	// so they are forwarded to upstream before any further client data.
	clientSrc := io.Reader(client)
	if n := br.Buffered(); n > 0 {
		head := make([]byte, n)
		br.Read(head) //nolint:errcheck
		clientSrc = io.MultiReader(bytes.NewReader(head), client)
	}

	// Bidirectional pipe: close both sides when either direction ends so the
	// other goroutine unblocks immediately.
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			client.Close()   //nolint:errcheck
			upstream.Close() //nolint:errcheck
		})
	}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); defer closeAll(); io.Copy(client, upstream) }()    //nolint:errcheck
	go func() { defer wg.Done(); defer closeAll(); io.Copy(upstream, clientSrc) }() //nolint:errcheck
	wg.Wait()
}

// discardClientAuth peeks at br for an AUTH command at connection start.
// If found, it consumes the command and writes "+OK\r\n" to w, preventing
// the client credential from reaching the upstream log.
// If not found, br is left unconsumed.
func discardClientAuth(br *bufio.Reader, w io.Writer) error {
	p4, err := br.Peek(4)
	if err != nil || len(p4) < 4 {
		return nil
	}

	// Array form: *2\r\n$4\r\nAUTH\r\n$N\r\npassword\r\n
	if bytes.Equal(p4, []byte("*2\r\n")) {
		p13, err := br.Peek(13)
		if err != nil || len(p13) < 13 {
			return nil
		}
		if bytes.Equal(p13[4:8], []byte("$4\r\n")) && strings.EqualFold(string(p13[8:12]), "AUTH") {
			return consumeArrayAuth(br, w)
		}
		return nil
	}

	// Inline form: AUTH ...\r\n
	if strings.EqualFold(string(p4), "AUTH") {
		p5, err := br.Peek(5)
		if err != nil {
			return nil
		}
		if p5[4] == ' ' || p5[4] == '\r' || p5[4] == '\n' {
			return consumeInlineAuth(br, w)
		}
	}

	return nil
}

// consumeArrayAuth reads a full RESP array AUTH command from br and sends "+OK\r\n" to w.
// br must be positioned at the start of the command (*2\r\n already confirmed by Peek).
func consumeArrayAuth(br *bufio.Reader, w io.Writer) error {
	// Read: *2\r\n, $4\r\n, AUTH\r\n
	for range 3 {
		if _, err := br.ReadString('\n'); err != nil {
			return err
		}
	}
	// Read $N\r\n
	lenLine, err := br.ReadString('\n')
	if err != nil {
		return err
	}
	var n int
	fmt.Sscanf(strings.TrimRight(lenLine, "\r\n"), "$%d", &n)
	// Read password + \r\n
	if _, err := io.ReadFull(br, make([]byte, n+2)); err != nil {
		return err
	}
	_, err = w.Write([]byte("+OK\r\n"))
	return err
}

// consumeInlineAuth reads a full inline AUTH line from br and sends "+OK\r\n" to w.
func consumeInlineAuth(br *bufio.Reader, w io.Writer) error {
	if _, err := br.ReadString('\n'); err != nil {
		return err
	}
	_, err := w.Write([]byte("+OK\r\n"))
	return err
}

func (p *redisProxy) Stop(_ context.Context) error {
	if p.listener == nil {
		return nil
	}
	return p.listener.Close()
}
