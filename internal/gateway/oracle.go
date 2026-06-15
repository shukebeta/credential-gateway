package gateway

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"credential-gateway/internal/config"
)

// TNS packet types.
const (
	tnsConnect = 1
	tnsAccept  = 2
	tnsRefuse  = 4
	tnsData    = 6
	tnsResend  = 11
)

// TTC function codes in DATA packet payloads (after the 2-byte data_flags prefix).
const (
	ttcO3LOG   = 0x76 // login request: username + session-key request
	ttcSessKey = 0x02 // session-key response from server
	ttcO3AUTH  = 0x73 // auth response: derived password
	ttcAuthOK  = 0x04 // auth accepted
)

const (
	tnsHeaderSize        = 8  // every TNS packet starts with an 8-byte header
	tnsConnectBodyFixed  = 62 // fixed fields in a CONNECT body before the connect data
	tnsConnectDataOffset = tnsHeaderSize + tnsConnectBodyFixed // 70: offset from packet start
)

type oracleProxy struct {
	cfg      config.OracleService
	log      *slog.Logger
	listener net.Listener
}

func (p *oracleProxy) Start() error {
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		return fmt.Errorf("oracle proxy: listen %s: %w", p.cfg.Listen, err)
	}
	p.listener = ln
	go p.accept()
	return nil
}

func (p *oracleProxy) accept() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *oracleProxy) handle(client net.Conn) {
	defer client.Close()

	// Step 1: read client CONNECT (type 1).
	pktType, _, err := tnsRead(client)
	if err != nil {
		p.log.Error("oracle proxy: read client CONNECT", "err", err)
		return
	}
	if pktType != tnsConnect {
		p.log.Error("oracle proxy: expected CONNECT from client", "got", pktType)
		return
	}

	// Step 2: dial upstream.
	upstream, err := net.Dial("tcp", p.cfg.Upstream)
	if err != nil {
		p.log.Error("oracle proxy: upstream dial failed", "upstream", p.cfg.Upstream, "err", err)
		return
	}
	defer upstream.Close()

	// Step 3: send our CONNECT to upstream with config service name.
	connectBody := tnsBuildConnect(p.cfg.Service)
	if err := tnsWrite(upstream, tnsConnect, connectBody); err != nil {
		p.log.Error("oracle proxy: write CONNECT to upstream", "err", err)
		return
	}

	// Step 4: handle upstream response — RESEND / REFUSE / ACCEPT.
	var acceptBody []byte
	for {
		pt, body, err := tnsRead(upstream)
		if err != nil {
			p.log.Error("oracle proxy: read upstream response", "err", err)
			return
		}
		switch pt {
		case tnsResend:
			if err := tnsWrite(upstream, tnsConnect, connectBody); err != nil {
				p.log.Error("oracle proxy: retransmit CONNECT", "err", err)
				return
			}
		case tnsRefuse:
			p.log.Error("oracle proxy: upstream refused connection", "upstream", p.cfg.Upstream)
			tnsWrite(client, tnsRefuse, body) //nolint:errcheck
			return
		case tnsAccept:
			acceptBody = body
		default:
			p.log.Error("oracle proxy: unexpected response to CONNECT", "type", pt)
			return
		}
		if acceptBody != nil {
			break
		}
	}

	// Step 5: forward ACCEPT to client.
	if err := tnsWrite(client, tnsAccept, acceptBody); err != nil {
		p.log.Error("oracle proxy: write ACCEPT to client", "err", err)
		return
	}

	// Step 6: NS negotiation + TTC credential injection.
	if err := p.doAuth(client, upstream); err != nil {
		p.log.Error("oracle proxy: auth failed", "err", err)
		return
	}

	p.log.Info("oracle proxy: client connected", "upstream", p.cfg.Upstream)

	// Step 7: bidirectional pipe.
	pipe(client, upstream)
}

// doAuth handles one round of NS (Native Services) negotiation followed by the
// TTC O3LOG / O3AUTH exchange. The proxy injects config credentials into the
// upstream auth and sends the client a dummy session-key + auth OK.
//
// V1 scope: unencrypted TNS path only; auth token = SHA1(password+salt).
// Real Oracle 11g/12c additionally requires AES-CBC session-key derivation.
func (p *oracleProxy) doAuth(client, upstream net.Conn) error {
	// NS round: upstream → client, then client → upstream.
	pt, nsBody, err := tnsRead(upstream)
	if err != nil {
		return fmt.Errorf("read NS from upstream: %w", err)
	}
	if pt != tnsData {
		return fmt.Errorf("expected NS DATA from upstream, got type %d", pt)
	}
	if err := tnsWrite(client, tnsData, nsBody); err != nil {
		return fmt.Errorf("forward NS to client: %w", err)
	}

	pt, nsResp, err := tnsRead(client)
	if err != nil {
		return fmt.Errorf("read NS from client: %w", err)
	}
	if pt != tnsData {
		return fmt.Errorf("expected NS DATA from client, got type %d", pt)
	}
	if err := tnsWrite(upstream, tnsData, nsResp); err != nil {
		return fmt.Errorf("forward NS to upstream: %w", err)
	}

	// O3LOG from client: read and validate, then replace with config username.
	pt, clientO3LOG, err := tnsRead(client)
	if err != nil {
		return fmt.Errorf("read O3LOG from client: %w", err)
	}
	if pt != tnsData {
		return fmt.Errorf("expected O3LOG DATA, got type %d", pt)
	}
	if len(clientO3LOG) < 3 || clientO3LOG[2] != ttcO3LOG {
		return fmt.Errorf("expected TTC O3LOG (0x%02x), got 0x%02x", ttcO3LOG, clientO3LOG[2])
	}
	_ = clientO3LOG // client credentials discarded; proxy uses config.User

	if err := tnsWrite(upstream, tnsData, tnsBuildO3LOG(p.cfg.User)); err != nil {
		return fmt.Errorf("write O3LOG to upstream: %w", err)
	}

	// Session-key challenge from upstream: extract 20-byte salt.
	pt, sessResp, err := tnsRead(upstream)
	if err != nil {
		return fmt.Errorf("read session key from upstream: %w", err)
	}
	if pt != tnsData {
		return fmt.Errorf("expected session-key DATA, got type %d", pt)
	}
	salt := tnsExtractSalt(sessResp)

	// Send a dummy session key to the client so it can compute its own O3AUTH.
	// The client's response is discarded; the proxy uses config credentials instead.
	if err := tnsWrite(client, tnsData, tnsBuildFakeSessionKey()); err != nil {
		return fmt.Errorf("write fake session key to client: %w", err)
	}

	// Discard client's O3AUTH (derived from client's password, not config password).
	if _, _, err := tnsRead(client); err != nil {
		return fmt.Errorf("read client O3AUTH: %w", err)
	}

	// Send our O3AUTH with config credentials to upstream.
	authData := oracleComputeAuth(p.cfg.Password, salt)
	if err := tnsWrite(upstream, tnsData, tnsBuildO3AUTH(p.cfg.User, authData)); err != nil {
		return fmt.Errorf("write O3AUTH to upstream: %w", err)
	}

	// Check upstream auth result.
	pt, authResult, err := tnsRead(upstream)
	if err != nil {
		return fmt.Errorf("read auth result: %w", err)
	}
	if pt != tnsData || !tnsIsAuthOK(authResult) {
		return fmt.Errorf("upstream rejected auth")
	}

	// Forward auth OK to client.
	if err := tnsWrite(client, tnsData, tnsBuildAuthOK()); err != nil {
		return fmt.Errorf("write auth OK to client: %w", err)
	}

	return nil
}

func (p *oracleProxy) Stop(_ context.Context) error {
	if p.listener == nil {
		return nil
	}
	return p.listener.Close()
}

// --- TNS wire helpers ---

// tnsRead reads one TNS packet (8-byte header + body).
func tnsRead(r io.Reader) (pktType byte, body []byte, err error) {
	hdr := make([]byte, tnsHeaderSize)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	length := int(binary.BigEndian.Uint16(hdr[0:2]))
	pktType = hdr[4]
	if length < tnsHeaderSize {
		err = fmt.Errorf("TNS packet length %d too small", length)
		return
	}
	bodyLen := length - tnsHeaderSize
	if bodyLen > 0 {
		body = make([]byte, bodyLen)
		_, err = io.ReadFull(r, body)
	}
	return
}

// tnsWrite writes one TNS packet with the given type and body.
func tnsWrite(w io.Writer, pktType byte, body []byte) error {
	length := tnsHeaderSize + len(body)
	var hdr [tnsHeaderSize]byte
	binary.BigEndian.PutUint16(hdr[0:], uint16(length))
	hdr[4] = pktType
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(body) > 0 {
		_, err := w.Write(body)
		return err
	}
	return nil
}

// tnsBuildConnect builds the body for a TNS CONNECT packet. The layout follows
// the go-ora client: 62 fixed bytes then a connect descriptor; connect-data
// offset from packet start = 70 (tnsHeaderSize + tnsConnectBodyFixed).
func tnsBuildConnect(service string) []byte {
	desc := fmt.Sprintf("(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=%s)))",
		strings.ToUpper(service))

	body := make([]byte, tnsConnectBodyFixed+len(desc))
	binary.BigEndian.PutUint16(body[0:], 313)                      // version
	binary.BigEndian.PutUint16(body[2:], 300)                      // min version
	binary.BigEndian.PutUint16(body[4:], 0x0C01)                   // service options
	binary.BigEndian.PutUint16(body[6:], 8192)                     // SDU (capped)
	binary.BigEndian.PutUint16(body[8:], 0xFFFF)                   // TDU (capped)
	body[10] = 0x4F                                                 // NT protocol chars (high)
	body[11] = 0x98                                                 // NT protocol chars (low)
	// [12:14] line turnaround = 0
	binary.BigEndian.PutUint16(body[14:], 1)                       // one in host byte order
	binary.BigEndian.PutUint16(body[16:], uint16(len(desc)))       // connect data length
	binary.BigEndian.PutUint16(body[18:], tnsConnectDataOffset)    // offset from packet start
	binary.BigEndian.PutUint32(body[20:], 512)                     // max connect data
	body[24] = 1                                                    // ACFL0
	body[25] = 1                                                    // ACFL1
	// [26:50] cross-facility items + connection IDs = 0
	binary.BigEndian.PutUint32(body[50:], 8192)                    // SDU (full uint32)
	binary.BigEndian.PutUint32(body[54:], 65535)                   // TDU (full uint32)
	// [58:62] reserved = 0
	copy(body[62:], desc)
	return body
}

// tnsDataBody prepends a 2-byte data_flags (0x0000) to a TTC payload.
func tnsDataBody(payload []byte) []byte {
	out := make([]byte, 2+len(payload))
	copy(out[2:], payload)
	return out
}

// tnsBuildO3LOG builds a TTC O3LOG (0x76) DATA body for the given username.
func tnsBuildO3LOG(username string) []byte {
	pl := make([]byte, 1+1+len(username))
	pl[0] = ttcO3LOG
	pl[1] = byte(len(username))
	copy(pl[2:], username)
	return tnsDataBody(pl)
}

// tnsBuildO3AUTH builds a TTC O3AUTH (0x73) DATA body with the derived auth token.
func tnsBuildO3AUTH(username string, authData []byte) []byte {
	pl := make([]byte, 1+1+len(username)+1+len(authData))
	pl[0] = ttcO3AUTH
	pl[1] = byte(len(username))
	copy(pl[2:], username)
	pl[2+len(username)] = byte(len(authData))
	copy(pl[3+len(username):], authData)
	return tnsDataBody(pl)
}

// tnsBuildFakeSessionKey builds a dummy session-key DATA body to send to the client.
// The client uses it to compute its own O3AUTH, which the proxy then discards.
func tnsBuildFakeSessionKey() []byte {
	pl := make([]byte, 1+20) // code + 20-byte dummy salt
	pl[0] = ttcSessKey
	return tnsDataBody(pl)
}

// tnsBuildAuthOK builds the auth-OK DATA packet forwarded to the client.
func tnsBuildAuthOK() []byte {
	return tnsDataBody([]byte{ttcAuthOK})
}

// tnsExtractSalt extracts the 20-byte salt from a session-key challenge DATA body.
// Layout: [0:2] data_flags | [2] ttcSessKey | [3:23] salt.
func tnsExtractSalt(body []byte) []byte {
	salt := make([]byte, 20)
	if len(body) >= 23 {
		copy(salt, body[3:23])
	}
	return salt
}

// tnsIsAuthOK reports whether a DATA body signals successful upstream auth.
func tnsIsAuthOK(body []byte) bool {
	return len(body) >= 3 && body[2] == ttcAuthOK
}

// oracleComputeAuth derives the auth token as SHA1(password + salt).
func oracleComputeAuth(password string, salt []byte) []byte {
	h := sha1.New()
	h.Write([]byte(password))
	h.Write(salt)
	return h.Sum(nil)
}
