package gateway

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"

	"credential-gateway/internal/config"
)

// fakeRedis is a minimal RESP server for testing.
type fakeRedis struct {
	ln       net.Listener
	addr     string
	password string // required upstream password; empty = no auth needed

	mu        sync.Mutex
	authsSeen []string // passwords received in AUTH commands
}

func newFakeRedis(t *testing.T, password string) *fakeRedis {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("fakeRedis listen: %v", err)
	}
	fr := &fakeRedis{ln: ln, addr: ln.Addr().String(), password: password}
	go fr.serve()
	t.Cleanup(func() { ln.Close() })
	return fr
}

func (f *fakeRedis) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeRedis) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	authed := f.password == ""
	for {
		cmd, args, err := readRESPCommand(br)
		if err != nil {
			return
		}
		switch strings.ToUpper(cmd) {
		case "AUTH":
			pw := ""
			if len(args) > 0 {
				pw = args[0]
			}
			f.mu.Lock()
			f.authsSeen = append(f.authsSeen, pw)
			f.mu.Unlock()
			if pw == f.password {
				authed = true
				conn.Write([]byte("+OK\r\n")) //nolint:errcheck
			} else {
				conn.Write([]byte("-ERR invalid password\r\n")) //nolint:errcheck
			}
		case "PING":
			if !authed {
				conn.Write([]byte("-NOAUTH Authentication required\r\n")) //nolint:errcheck
				return
			}
			conn.Write([]byte("+PONG\r\n")) //nolint:errcheck
		default:
			conn.Write([]byte("-ERR unknown\r\n")) //nolint:errcheck
		}
	}
}

// authCount returns the number of AUTH commands the fake server has received.
func (f *fakeRedis) authCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.authsSeen)
}

// readRESPCommand reads one RESP array or inline command from br.
func readRESPCommand(br *bufio.Reader) (string, []string, error) {
	line, err := br.ReadString('\n')
	if err != nil {
		return "", nil, err
	}
	line = strings.TrimRight(line, "\r\n")

	if !strings.HasPrefix(line, "*") {
		// Inline
		parts := strings.Fields(line)
		if len(parts) == 0 {
			return "", nil, io.EOF
		}
		return parts[0], parts[1:], nil
	}

	var n int
	fmt.Sscanf(line, "*%d", &n)
	elems := make([]string, n)
	for i := range n {
		lenLine, err := br.ReadString('\n')
		if err != nil {
			return "", nil, err
		}
		var l int
		fmt.Sscanf(strings.TrimRight(lenLine, "\r\n"), "$%d", &l)
		data := make([]byte, l+2)
		if _, err := io.ReadFull(br, data); err != nil {
			return "", nil, err
		}
		elems[i] = string(data[:l])
	}
	if len(elems) == 0 {
		return "", nil, io.EOF
	}
	return elems[0], elems[1:], nil
}

func startRedisProxy(t *testing.T, upstream, password string) *redisProxy {
	t.Helper()
	p := &redisProxy{
		cfg: config.RedisService{
			Listen:   "127.0.0.1:0",
			Upstream: upstream,
			Password: password,
		},
		log: testLogger(),
	}
	if err := p.Start(); err != nil {
		t.Fatalf("redis proxy start: %v", err)
	}
	t.Cleanup(func() { p.Stop(context.Background()) }) //nolint:errcheck
	return p
}

func ping(t *testing.T, addr string) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		t.Fatalf("write PING: %v", err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

func TestRedisProxy_InjectsUpstreamAUTH(t *testing.T) {
	upstream := newFakeRedis(t, "secret")
	p := startRedisProxy(t, upstream.addr, "secret")

	resp := ping(t, p.listener.Addr().String())
	if resp != "+PONG" {
		t.Errorf("PING response = %q, want +PONG", resp)
	}
	if upstream.authCount() != 1 {
		t.Errorf("upstream received %d AUTH commands, want 1", upstream.authCount())
	}
}

func TestRedisProxy_InterceptsClientArrayAUTH(t *testing.T) {
	upstream := newFakeRedis(t, "proxypass")
	p := startRedisProxy(t, upstream.addr, "proxypass")

	conn, err := net.Dial("tcp", p.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Send AUTH from client (should be intercepted)
	clientAuth := "*2\r\n$4\r\nAUTH\r\n$10\r\nclientpass\r\n"
	if _, err := conn.Write([]byte(clientAuth)); err != nil {
		t.Fatalf("write client AUTH: %v", err)
	}
	br := bufio.NewReader(conn)
	authResp, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read AUTH response: %v", err)
	}
	if strings.TrimRight(authResp, "\r\n") != "+OK" {
		t.Errorf("client AUTH response = %q, want +OK", authResp)
	}

	// Now send PING; it should still work (upstream was authed by proxy)
	if _, err := conn.Write([]byte("*1\r\n$4\r\nPING\r\n")); err != nil {
		t.Fatalf("write PING: %v", err)
	}
	pingResp, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read PING response: %v", err)
	}
	if strings.TrimRight(pingResp, "\r\n") != "+PONG" {
		t.Errorf("PING response = %q, want +PONG", pingResp)
	}

	// The upstream should have received exactly one AUTH (from proxy), not the client's
	if upstream.authCount() != 1 {
		t.Errorf("upstream received %d AUTH commands, want 1 (proxy only)", upstream.authCount())
	}
}

func TestRedisProxy_InterceptsClientInlineAUTH(t *testing.T) {
	upstream := newFakeRedis(t, "proxypass")
	p := startRedisProxy(t, upstream.addr, "proxypass")

	conn, err := net.Dial("tcp", p.listener.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// Inline AUTH
	if _, err := conn.Write([]byte("AUTH clientpass\r\n")); err != nil {
		t.Fatalf("write inline AUTH: %v", err)
	}
	br := bufio.NewReader(conn)
	resp, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if strings.TrimRight(resp, "\r\n") != "+OK" {
		t.Errorf("inline AUTH response = %q, want +OK", resp)
	}

	// Client password must not reach upstream
	if upstream.authCount() != 1 {
		t.Errorf("upstream received %d AUTH commands, want 1 (proxy only)", upstream.authCount())
	}
}

func TestRedisProxy_NoPasswordConfig(t *testing.T) {
	upstream := newFakeRedis(t, "") // upstream requires no password
	p := startRedisProxy(t, upstream.addr, "")

	resp := ping(t, p.listener.Addr().String())
	if resp != "+PONG" {
		t.Errorf("PING response = %q, want +PONG", resp)
	}
	if upstream.authCount() != 0 {
		t.Errorf("upstream received %d AUTH commands, want 0", upstream.authCount())
	}
}
