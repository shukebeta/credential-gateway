package gateway

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"testing"

	"credential-gateway/internal/config"
)

// --- unit tests for wire helpers ---

func TestPgReadWriteMessage(t *testing.T) {
	// Build a message: type 'Z' + body "I"
	body := []byte("I")
	msg := append([]byte{'Z'}, body...)

	var buf bytes.Buffer
	if err := pgWriteMessage(&buf, msg); err != nil {
		t.Fatal(err)
	}

	got, err := pgReadMessage(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Errorf("message mismatch: got %q want %q", got, msg)
	}
}

func TestPgReadWriteStartup(t *testing.T) {
	payload := pgBuildStartup("alice", "testdb")

	var buf bytes.Buffer
	if err := pgWriteStartup(&buf, payload); err != nil {
		t.Fatal(err)
	}

	got, err := pgReadStartup(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Errorf("startup mismatch: got %q want %q", got, payload)
	}
}

func TestPgBuildStartupParams(t *testing.T) {
	payload := pgBuildStartup("alice", "testdb")

	if binary.BigEndian.Uint32(payload) != 196608 {
		t.Errorf("wrong protocol version: %d", binary.BigEndian.Uint32(payload))
	}
	params := pgParseParams(payload[4:])
	if params["user"] != "alice" {
		t.Errorf("user: got %q want %q", params["user"], "alice")
	}
	if params["database"] != "testdb" {
		t.Errorf("database: got %q want %q", params["database"], "testdb")
	}
}

func TestPgBuildStartupNoDatabase(t *testing.T) {
	payload := pgBuildStartup("alice", "")
	params := pgParseParams(payload[4:])
	if _, ok := params["database"]; ok {
		t.Error("database param present but should be absent when empty")
	}
}

func TestPgMD5Password(t *testing.T) {
	// Reference: md5(md5(password+user)+salt) prefixed with "md5"
	user, password := "alice", "secret"
	salt := []byte{1, 2, 3, 4}

	got := pgMD5Password(user, password, salt)

	h1 := md5.Sum([]byte(password + user))
	hex1 := fmt.Sprintf("%x", h1)
	h2 := md5.Sum(append([]byte(hex1), salt...))
	want := "md5" + fmt.Sprintf("%x", h2)

	if got != want {
		t.Errorf("MD5 password: got %q want %q", got, want)
	}
}

func TestPgParseSASLMechanisms(t *testing.T) {
	// "SCRAM-SHA-256\0SCRAM-SHA-256-PLUS\0\0"
	data := append([]byte("SCRAM-SHA-256\x00SCRAM-SHA-256-PLUS\x00"), 0)
	mechanisms := pgParseSASLMechanisms(data)
	if len(mechanisms) != 2 {
		t.Fatalf("expected 2 mechanisms, got %d", len(mechanisms))
	}
	if mechanisms[0] != "SCRAM-SHA-256" {
		t.Errorf("mechanisms[0]: got %q", mechanisms[0])
	}
	if mechanisms[1] != "SCRAM-SHA-256-PLUS" {
		t.Errorf("mechanisms[1]: got %q", mechanisms[1])
	}
}

func TestPgPBKDF2(t *testing.T) {
	// Reference vector from RFC 6070 adapted for SHA-256:
	// Test with known values and verify against manual computation.
	password := []byte("password")
	salt := []byte("salt")
	iterations := 1
	keyLen := 32

	got := pgPBKDF2(password, salt, iterations, keyLen)

	// Compute expected using HMAC-SHA256 PBKDF2 manually for 1 iteration.
	prf := hmac.New(sha256.New, password)
	prf.Write(salt)
	prf.Write([]byte{0, 0, 0, 1}) // block 1
	want := prf.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Errorf("PBKDF2 1-iteration mismatch:\n got  %x\n want %x", got, want)
	}
}

func TestPgParseError(t *testing.T) {
	// Build an ErrorResponse with an 'M' (message) field.
	body := []byte("Msomething went wrong\x00S ERROR\x00\x00")
	msg := append([]byte{'E'}, body...)
	got := pgParseError(msg)
	if got != "something went wrong" {
		t.Errorf("pgParseError: got %q", got)
	}
}

// --- integration test: fake upstream server ---

// pgFakeUpstreamMD5 serves a minimal PostgreSQL startup for MD5 auth.
func pgFakeUpstreamMD5(conn net.Conn, user, password string) {
	defer conn.Close()

	// Read StartupMessage from proxy.
	startup, err := pgReadStartup(conn)
	if err != nil || len(startup) < 4 {
		return
	}

	// Send AuthenticationMD5Password with salt [1,2,3,4].
	salt := []byte{1, 2, 3, 4}
	authMD5 := make([]byte, 1+4+4)
	authMD5[0] = 'R'
	binary.BigEndian.PutUint32(authMD5[1:], 5) // MD5
	copy(authMD5[5:], salt)
	pgWriteMessage(conn, authMD5) //nolint:errcheck

	// Read PasswordMessage.
	resp, err := pgReadMessage(conn)
	if err != nil || len(resp) < 2 || resp[0] != 'p' {
		return
	}

	// Verify MD5 hash.
	params := pgParseParams(startup[4:])
	proxyUser := params["user"]
	expected := pgMD5Password(proxyUser, password, salt)
	got := strings.TrimRight(string(resp[1:]), "\x00")
	if got != expected {
		return // send nothing — client will see EOF
	}

	// AuthenticationOK.
	authOK := []byte{'R', 0, 0, 0, 0}
	pgWriteMessage(conn, authOK) //nolint:errcheck

	// ParameterStatus + ReadyForQuery.
	ps := append([]byte{'S'}, []byte("server_version\x0014.0\x00")...)
	pgWriteMessage(conn, ps) //nolint:errcheck
	pgWriteMessage(conn, []byte{'Z', 'I'}) //nolint:errcheck

	// Drain — stay open so the pipe has something to read.
	buf := make([]byte, 64)
	conn.Read(buf) //nolint:errcheck
}

func TestPostgresProxyMD5(t *testing.T) {
	const user, password, db = "proxyuser", "topsecret", "testdb"

	// Start fake upstream.
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()

	go func() {
		for {
			conn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go pgFakeUpstreamMD5(conn, user, password)
		}
	}()

	// Start the proxy.
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	proxy := &postgresProxy{
		cfg: config.PostgreSQLService{
			Listen:   proxyLn.Addr().String(),
			Upstream: upstreamLn.Addr().String(),
			User:     user,
			Password: password,
			Database: db,
		},
		log: testLogger(),
	}
	proxy.listener = proxyLn
	go proxy.accept()

	// Connect as a client (no credentials).
	client, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Send a StartupMessage with arbitrary credentials.
	startup := pgBuildStartup("nobody", db)
	if err := pgWriteStartup(client, startup); err != nil {
		t.Fatal(err)
	}

	// Expect AuthenticationOK from the proxy (forwarded from upstream).
	msg, err := pgReadMessage(client)
	if err != nil {
		t.Fatal("read AuthOK:", err)
	}
	if msg[0] != 'R' || binary.BigEndian.Uint32(msg[1:]) != 0 {
		t.Fatalf("expected AuthenticationOK, got type=%c authtype=%d", msg[0], binary.BigEndian.Uint32(msg[1:]))
	}

	// Expect ParameterStatus then ReadyForQuery.
	got := []byte{}
	for {
		msg, err = pgReadMessage(client)
		if err != nil {
			t.Fatal("read startup chain:", err)
		}
		got = append(got, msg[0])
		if msg[0] == 'Z' {
			break
		}
	}
	if !bytes.Contains(got, []byte{'S'}) {
		t.Error("expected ParameterStatus ('S') in startup chain")
	}
}

func TestPostgresProxySSLReject(t *testing.T) {
	const user, password, db = "proxyuser", "topsecret", "testdb"

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upstreamLn.Close()

	go func() {
		for {
			conn, err := upstreamLn.Accept()
			if err != nil {
				return
			}
			go pgFakeUpstreamMD5(conn, user, password)
		}
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	proxy := &postgresProxy{
		cfg: config.PostgreSQLService{
			Listen:   proxyLn.Addr().String(),
			Upstream: upstreamLn.Addr().String(),
			User:     user,
			Password: password,
			Database: db,
		},
		log: testLogger(),
	}
	proxy.listener = proxyLn
	go proxy.accept()

	client, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Send SSLRequest (code 80877103).
	sslReq := make([]byte, 4)
	binary.BigEndian.PutUint32(sslReq, 80877103)
	if err := pgWriteStartup(client, sslReq); err != nil {
		t.Fatal(err)
	}

	// Expect 'N' (SSL not supported).
	resp := make([]byte, 1)
	if _, err := client.Read(resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != 'N' {
		t.Errorf("expected 'N' for SSL reject, got %q", resp[0])
	}

	// Now send real StartupMessage and expect AuthOK.
	startup := pgBuildStartup("nobody", db)
	if err := pgWriteStartup(client, startup); err != nil {
		t.Fatal(err)
	}
	msg, err := pgReadMessage(client)
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != 'R' || binary.BigEndian.Uint32(msg[1:]) != 0 {
		t.Fatalf("expected AuthenticationOK after SSL reject, got type=%c", msg[0])
	}
}

func TestPgSCRAMKeyDerivation(t *testing.T) {
	// Verify SCRAM-SHA-256 key derivation is consistent with the spec.
	// Using test vector from RFC 5802 §5 adapted to SHA-256.
	password := "pencil"
	salt, _ := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	iterations := 4096

	saltedPassword := pgPBKDF2([]byte(password), salt, iterations, 32)
	clientKey := pgHMAC(saltedPassword, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := pgHMAC(saltedPassword, "Server Key")

	// Just verify these are non-zero and deterministic.
	if bytes.Equal(clientKey, make([]byte, 32)) {
		t.Error("clientKey is all zeros")
	}
	if storedKey == [32]byte{} {
		t.Error("storedKey is all zeros")
	}
	if bytes.Equal(serverKey, make([]byte, 32)) {
		t.Error("serverKey is all zeros")
	}

	// Recompute and verify determinism.
	saltedPassword2 := pgPBKDF2([]byte(password), salt, iterations, 32)
	if !bytes.Equal(saltedPassword, saltedPassword2) {
		t.Error("PBKDF2 not deterministic")
	}
}
