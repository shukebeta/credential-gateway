package gateway

import (
	"bytes"
	"crypto/sha1"
	"net"
	"testing"

	"credential-gateway/internal/config"
)

// --- unit tests for TNS wire helpers ---

func TestTNSReadWrite(t *testing.T) {
	body := []byte("hello oracle")
	var buf bytes.Buffer
	if err := tnsWrite(&buf, tnsData, body); err != nil {
		t.Fatal(err)
	}

	pktType, got, err := tnsRead(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if pktType != tnsData {
		t.Errorf("type: got %d, want %d", pktType, tnsData)
	}
	if !bytes.Equal(got, body) {
		t.Errorf("body mismatch: got %q, want %q", got, body)
	}
}

func TestTNSReadWriteEmptyBody(t *testing.T) {
	var buf bytes.Buffer
	if err := tnsWrite(&buf, tnsAccept, nil); err != nil {
		t.Fatal(err)
	}
	pt, body, err := tnsRead(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if pt != tnsAccept {
		t.Errorf("type: got %d, want %d", pt, tnsAccept)
	}
	if len(body) != 0 {
		t.Errorf("expected empty body, got %d bytes", len(body))
	}
}

func TestTNSBuildConnect(t *testing.T) {
	service := "MYSERVICE"
	body := tnsBuildConnect(service)

	if len(body) < tnsConnectBodyFixed {
		t.Fatalf("body too short: %d", len(body))
	}

	// Verify connect data length field
	cdLen := int(uint16(body[16])<<8 | uint16(body[17]))
	if cdLen == 0 {
		t.Error("connect data length should be non-zero")
	}

	// Verify offset field = 70
	cdOff := int(uint16(body[18])<<8 | uint16(body[19]))
	if cdOff != tnsConnectDataOffset {
		t.Errorf("connect data offset: got %d, want %d", cdOff, tnsConnectDataOffset)
	}

	// Verify service name appears in the connect data
	desc := string(body[tnsConnectBodyFixed:])
	if !bytes.Contains([]byte(desc), []byte(service)) {
		t.Errorf("connect data %q does not contain service %q", desc, service)
	}
}

// --- unit tests for TTC helpers ---

func TestTNSBuildO3LOGContainsUser(t *testing.T) {
	body := tnsBuildO3LOG("alice")
	// body[0:2] = data_flags, body[2] = function code, body[3] = len, body[4..] = username
	if len(body) < 5 {
		t.Fatalf("O3LOG body too short: %d bytes", len(body))
	}
	if body[2] != ttcO3LOG {
		t.Errorf("function code: got 0x%02x, want 0x%02x", body[2], ttcO3LOG)
	}
	if !bytes.Contains(body, []byte("alice")) {
		t.Error("O3LOG body does not contain username")
	}
}

func TestTNSBuildO3AUTHContainsUserAndAuth(t *testing.T) {
	auth := make([]byte, 20)
	for i := range auth {
		auth[i] = byte(i + 1)
	}
	body := tnsBuildO3AUTH("bob", auth)
	if body[2] != ttcO3AUTH {
		t.Errorf("function code: got 0x%02x, want 0x%02x", body[2], ttcO3AUTH)
	}
	if !bytes.Contains(body, []byte("bob")) {
		t.Error("O3AUTH body does not contain username")
	}
	if !bytes.Contains(body, auth) {
		t.Error("O3AUTH body does not contain auth data")
	}
}

func TestTNSExtractSalt(t *testing.T) {
	salt := make([]byte, 20)
	for i := range salt {
		salt[i] = byte(i + 10)
	}
	// Build a session key DATA body manually
	body := make([]byte, 2+1+20)
	body[2] = ttcSessKey
	copy(body[3:], salt)

	got := tnsExtractSalt(body)
	if !bytes.Equal(got, salt) {
		t.Errorf("salt mismatch:\n got  %x\n want %x", got, salt)
	}
}

func TestTNSIsAuthOK(t *testing.T) {
	ok := tnsDataBody([]byte{ttcAuthOK})
	if !tnsIsAuthOK(ok) {
		t.Error("expected auth OK to be recognised")
	}
	notOk := tnsDataBody([]byte{0xFF})
	if tnsIsAuthOK(notOk) {
		t.Error("expected non-OK to be rejected")
	}
}

// --- unit test for auth derivation ---

func TestOracleComputeAuth(t *testing.T) {
	password := "s3cr3t"
	salt := make([]byte, 20)
	for i := range salt {
		salt[i] = byte(i + 1)
	}

	got := oracleComputeAuth(password, salt)

	h := sha1.New()
	h.Write([]byte(password))
	h.Write(salt)
	want := h.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Errorf("auth mismatch:\n got  %x\n want %x", got, want)
	}
}

// --- fake upstream helpers ---

// oracleFakeUpstreamRefuse reads a CONNECT packet then sends REFUSE.
func oracleFakeUpstreamRefuse(conn net.Conn) {
	defer conn.Close()
	tnsRead(conn)                              //nolint:errcheck
	tnsWrite(conn, tnsRefuse, []byte{0, 0, 0, 0}) //nolint:errcheck
}

// oracleFakeUpstream simulates a minimal Oracle server: ACCEPT, NS negotiation,
// O3LOG/O3AUTH exchange with credential verification, auth OK, then stay open.
func oracleFakeUpstream(conn net.Conn, user, password string) {
	defer conn.Close()

	// Read CONNECT from proxy.
	pt, _, err := tnsRead(conn)
	if err != nil || pt != tnsConnect {
		return
	}

	// Send ACCEPT.
	if err := tnsWrite(conn, tnsAccept, []byte{0, 0, 0, 0}); err != nil {
		return
	}

	// NS negotiation: send one DATA, read one DATA.
	if err := tnsWrite(conn, tnsData, tnsDataBody([]byte{0x00, 0x01})); err != nil {
		return
	}
	if _, _, err := tnsRead(conn); err != nil {
		return
	}

	// Read O3LOG from proxy; verify function code and extract username.
	_, o3log, err := tnsRead(conn)
	if err != nil || len(o3log) < 4 || o3log[2] != ttcO3LOG {
		return
	}
	ulen := int(o3log[3])
	if 4+ulen > len(o3log) {
		return
	}
	gotUser := string(o3log[4 : 4+ulen])

	// Send session key with a fixed known salt.
	salt := make([]byte, 20)
	for i := range salt {
		salt[i] = byte(i + 1)
	}
	sessBody := make([]byte, 2+1+20)
	sessBody[2] = ttcSessKey
	copy(sessBody[3:], salt)
	if err := tnsWrite(conn, tnsData, sessBody); err != nil {
		return
	}

	// Read O3AUTH from proxy; extract and verify credentials.
	_, o3auth, err := tnsRead(conn)
	if err != nil || len(o3auth) < 4 || o3auth[2] != ttcO3AUTH {
		return
	}
	aulen := int(o3auth[3])
	if 4+aulen > len(o3auth) {
		return
	}
	gotUser2 := string(o3auth[4 : 4+aulen])
	authOff := 4 + aulen
	if authOff+1 > len(o3auth) {
		return
	}
	authLen := int(o3auth[authOff])
	if authOff+1+authLen > len(o3auth) {
		return
	}
	gotAuth := o3auth[authOff+1 : authOff+1+authLen]

	expectedAuth := oracleComputeAuth(password, salt)
	if gotUser != user || gotUser2 != user || !bytes.Equal(gotAuth, expectedAuth) {
		return // credential mismatch — client will see EOF
	}

	// Send auth OK.
	tnsWrite(conn, tnsData, tnsBuildAuthOK()) //nolint:errcheck

	// Stay open for the pipe phase.
	buf := make([]byte, 64)
	conn.Read(buf) //nolint:errcheck
}

// --- integration tests ---

func TestOracleProxyRefuse(t *testing.T) {
	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	go func() {
		for {
			conn, err := upLn.Accept()
			if err != nil {
				return
			}
			go oracleFakeUpstreamRefuse(conn)
		}
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	proxy := &oracleProxy{
		cfg: config.OracleService{
			Listen:   proxyLn.Addr().String(),
			Upstream: upLn.Addr().String(),
			User:     "user",
			Password: "pass",
			Service:  "TESTDB",
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

	// Send a minimal CONNECT.
	if err := tnsWrite(client, tnsConnect, tnsBuildConnect("TESTDB")); err != nil {
		t.Fatal(err)
	}

	// Expect the proxy to forward the REFUSE.
	pt, _, err := tnsRead(client)
	if err != nil {
		t.Fatal(err)
	}
	if pt != tnsRefuse {
		t.Errorf("expected REFUSE (type %d), got type %d", tnsRefuse, pt)
	}
}

func TestOracleProxyHappyPath(t *testing.T) {
	const user, password, service = "proxyuser", "topsecret", "ORCLPDB1"

	upLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer upLn.Close()

	go func() {
		for {
			conn, err := upLn.Accept()
			if err != nil {
				return
			}
			go oracleFakeUpstream(conn, user, password)
		}
	}()

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer proxyLn.Close()

	proxy := &oracleProxy{
		cfg: config.OracleService{
			Listen:   proxyLn.Addr().String(),
			Upstream: upLn.Addr().String(),
			User:     user,
			Password: password,
			Service:  service,
		},
		log: testLogger(),
	}
	proxy.listener = proxyLn
	go proxy.accept()

	// Connect as a client with arbitrary (wrong) credentials.
	client, err := net.Dial("tcp", proxyLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	// Client sends CONNECT with any service name.
	if err := tnsWrite(client, tnsConnect, tnsBuildConnect("ANYSVC")); err != nil {
		t.Fatal(err)
	}

	// Expect ACCEPT forwarded by proxy.
	pt, _, err := tnsRead(client)
	if err != nil {
		t.Fatal("read ACCEPT:", err)
	}
	if pt != tnsAccept {
		t.Fatalf("expected ACCEPT (type %d), got type %d", tnsAccept, pt)
	}

	// NS round: receive upstream NS, send NS response.
	if _, _, err := tnsRead(client); err != nil {
		t.Fatal("read NS:", err)
	}
	if err := tnsWrite(client, tnsData, tnsDataBody([]byte{0x00, 0x02})); err != nil {
		t.Fatal(err)
	}

	// Send O3LOG with wrong credentials (proxy should replace with config credentials).
	if err := tnsWrite(client, tnsData, tnsBuildO3LOG("wronguser")); err != nil {
		t.Fatal(err)
	}

	// Receive dummy session key from proxy.
	pt, sessBody, err := tnsRead(client)
	if err != nil {
		t.Fatal("read session key:", err)
	}
	if pt != tnsData || len(sessBody) < 3 || sessBody[2] != ttcSessKey {
		t.Fatalf("expected session-key DATA, got type=%d body=%x", pt, sessBody)
	}

	// Send O3AUTH with wrong derived key (proxy discards this).
	if err := tnsWrite(client, tnsData, tnsBuildO3AUTH("wronguser", make([]byte, 20))); err != nil {
		t.Fatal(err)
	}

	// Expect auth OK from proxy.
	pt, body, err := tnsRead(client)
	if err != nil {
		t.Fatal("read auth OK:", err)
	}
	if pt != tnsData || !tnsIsAuthOK(body) {
		t.Fatalf("expected auth OK, got type=%d body=%x", pt, body)
	}
}
