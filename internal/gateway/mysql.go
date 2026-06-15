package gateway

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
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

	// --- Step 1: read HandshakeV10 from upstream ---
	seq, handshake, err := mysqlReadPacket(upstream)
	if err != nil {
		p.log.Error("mysql proxy: read upstream handshake", "err", err)
		return
	}

	nonce, err := mysqlParseNonce(handshake)
	if err != nil {
		p.log.Error("mysql proxy: parse nonce", "err", err)
		return
	}

	// Mask CLIENT_SSL so the client does not attempt a TLS upgrade.
	mysqlClearSSL(handshake)

	// --- Step 2: forward modified handshake to client ---
	if err := mysqlWritePacket(client, seq, handshake); err != nil {
		p.log.Error("mysql proxy: write handshake to client", "err", err)
		return
	}

	// --- Step 3: read client HandshakeResponse (discard credentials) ---
	_, clientResp, err := mysqlReadPacket(client)
	if err != nil {
		p.log.Error("mysql proxy: read client response", "err", err)
		return
	}

	// Extract the database name the client requested (we may override with config).
	clientCaps := binary.LittleEndian.Uint32(clientResp[:4])
	db := p.cfg.Database
	if db == "" {
		db = mysqlParseDatabase(clientResp, clientCaps)
	}

	// --- Step 4: build our own HandshakeResponse with config credentials ---
	ourResp := mysqlBuildResponse(p.cfg.User, p.cfg.Password, nonce, db)

	// --- Step 5: send to upstream (seq=1 from client's slot) ---
	if err := mysqlWritePacket(upstream, 1, ourResp); err != nil {
		p.log.Error("mysql proxy: write auth to upstream", "err", err)
		return
	}

	// --- Step 6: read upstream OK/ERR, forward to client ---
	seq, result, err := mysqlReadPacket(upstream)
	if err != nil {
		p.log.Error("mysql proxy: read upstream auth result", "err", err)
		return
	}
	if err := mysqlWritePacket(client, seq, result); err != nil {
		p.log.Error("mysql proxy: write auth result to client", "err", err)
		return
	}

	// ERR packet starts with 0xff.
	if len(result) > 0 && result[0] == 0xff {
		p.log.Error("mysql proxy: upstream rejected auth", "upstream", p.cfg.Upstream)
		return
	}

	// Handle auth-switch-request: upstream may ask the client to re-authenticate
	// using a different plugin. We don't forward that to the client — just close.
	if len(result) > 0 && result[0] == 0xfe {
		p.log.Error("mysql proxy: upstream requested unsupported auth switch")
		return
	}

	p.log.Info("mysql proxy: client connected", "upstream", p.cfg.Upstream)

	// --- Step 7: bidirectional pipe ---
	pipe(client, upstream)
}

func (p *mysqlProxy) Stop(_ context.Context) error {
	if p.listener == nil {
		return nil
	}
	return p.listener.Close()
}

// mysqlReadPacket reads one MySQL packet: 3-byte length + 1-byte seq + payload.
func mysqlReadPacket(r io.Reader) (seq byte, payload []byte, err error) {
	hdr := make([]byte, 4)
	if _, err = io.ReadFull(r, hdr); err != nil {
		return
	}
	length := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	seq = hdr[3]
	payload = make([]byte, length)
	_, err = io.ReadFull(r, payload)
	return
}

// mysqlWritePacket writes one MySQL packet with the given sequence number.
func mysqlWritePacket(w io.Writer, seq byte, payload []byte) error {
	hdr := [4]byte{
		byte(len(payload)),
		byte(len(payload) >> 8),
		byte(len(payload) >> 16),
		seq,
	}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// mysqlParseNonce extracts the 20-byte auth-plugin-data (nonce) from a HandshakeV10 payload.
func mysqlParseNonce(payload []byte) ([]byte, error) {
	if len(payload) < 1 || payload[0] != 0x0a {
		return nil, fmt.Errorf("not a HandshakeV10 (first byte 0x%02x)", payload[0])
	}

	// Skip server version (null-terminated string), starting at byte 1.
	pos := 1
	for pos < len(payload) && payload[pos] != 0 {
		pos++
	}
	pos++ // skip null terminator

	if pos+13 > len(payload) {
		return nil, fmt.Errorf("handshake packet too short")
	}

	pos += 4 // connection ID

	part1 := make([]byte, 8)
	copy(part1, payload[pos:pos+8])
	pos += 8
	pos++ // filler 0x00

	// capability_flags_1 (2 bytes)
	pos += 2
	// character set (1 byte)
	pos++
	// status flags (2 bytes)
	pos += 2
	// capability_flags_2 (2 bytes)
	capHigh := uint16(payload[pos]) | uint16(payload[pos+1])<<8
	pos += 2

	// CLIENT_PLUGIN_AUTH = 0x00080000; in the upper 2 bytes that is bit 0x0008.
	authDataLen := 0
	if capHigh&0x0008 != 0 {
		authDataLen = int(payload[pos])
	}
	pos++      // auth_plugin_data_len
	pos += 10  // reserved

	part2Len := authDataLen - 8
	if part2Len < 13 {
		part2Len = 13
	}
	if pos+part2Len > len(payload) {
		return nil, fmt.Errorf("handshake nonce data out of range")
	}

	nonce := make([]byte, 20)
	copy(nonce[:8], part1)
	// part2 is part2Len bytes; last byte is a null terminator, so take only first 12.
	copy(nonce[8:], payload[pos:pos+12])

	return nonce, nil
}

// mysqlClearSSL clears the CLIENT_SSL capability bit (0x0800) from a HandshakeV10 payload
// to prevent clients from attempting a TLS upgrade.
func mysqlClearSSL(payload []byte) {
	pos := 1
	for pos < len(payload) && payload[pos] != 0 {
		pos++
	}
	pos++ // skip null terminator
	pos += 4 + 8 + 1 // connection ID + auth part 1 + filler

	// capability_flags_1: 2 bytes starting at pos
	if pos+1 < len(payload) {
		capLow := uint16(payload[pos]) | uint16(payload[pos+1])<<8
		capLow &^= 0x0800 // clear CLIENT_SSL
		payload[pos] = byte(capLow)
		payload[pos+1] = byte(capLow >> 8)
	}
}

// mysqlParseDatabase extracts the database name from a HandshakeResponse41 payload,
// returning empty string if CLIENT_CONNECT_WITH_DB is not set or not present.
func mysqlParseDatabase(payload []byte, caps uint32) string {
	const clientConnectWithDB = 0x00000008
	if caps&clientConnectWithDB == 0 {
		return ""
	}

	pos := 4 + 4 + 1 + 23 // cap flags + max pkt + charset + reserved
	if pos >= len(payload) {
		return ""
	}

	// skip username (null-terminated)
	for pos < len(payload) && payload[pos] != 0 {
		pos++
	}
	pos++ // skip null

	if pos >= len(payload) {
		return ""
	}

	// auth response: length-encoded
	authLen := int(payload[pos])
	pos += 1 + authLen

	if pos >= len(payload) {
		return ""
	}

	// database: null-terminated
	start := pos
	for pos < len(payload) && payload[pos] != 0 {
		pos++
	}
	return string(payload[start:pos])
}

// mysqlBuildResponse constructs a HandshakeResponse41 for the given credentials.
func mysqlBuildResponse(user, password string, nonce []byte, database string) []byte {
	const (
		clientLongPassword  = 0x00000001
		clientConnectWithDB = 0x00000008
		clientProtocol41    = 0x00000200
		clientTransactions  = 0x00002000
		clientSecureConn    = 0x00008000
		clientPluginAuth    = 0x00080000
	)

	caps := uint32(clientLongPassword | clientProtocol41 | clientTransactions | clientSecureConn | clientPluginAuth)
	if database != "" {
		caps |= clientConnectWithDB
	}

	authResp := mysqlScramble(nonce, password)

	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, caps)           //nolint:errcheck
	binary.Write(&buf, binary.LittleEndian, uint32(1<<24-1)) //nolint:errcheck // max packet size
	buf.WriteByte(45)                                         // utf8mb4
	buf.Write(make([]byte, 23))                               // reserved
	buf.WriteString(user)
	buf.WriteByte(0)
	buf.WriteByte(byte(len(authResp)))
	buf.Write(authResp)
	if database != "" {
		buf.WriteString(database)
		buf.WriteByte(0)
	}
	buf.WriteString("mysql_native_password")
	buf.WriteByte(0)

	return buf.Bytes()
}

// mysqlScramble computes the mysql_native_password auth response:
// SHA1(password) XOR SHA1(nonce + SHA1(SHA1(password)))
func mysqlScramble(nonce []byte, password string) []byte {
	if password == "" {
		return nil
	}
	h1 := sha1.Sum([]byte(password))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(nonce)
	h.Write(h2[:])
	s := h.Sum(nil)
	for i := range s {
		s[i] ^= h1[i]
	}
	return s
}
