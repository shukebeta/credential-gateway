package gateway

import (
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"

	"credential-gateway/internal/config"
)

type postgresProxy struct {
	cfg      config.PostgreSQLService
	log      *slog.Logger
	listener net.Listener
}

func (p *postgresProxy) Start() error {
	ln, err := net.Listen("tcp", p.cfg.Listen)
	if err != nil {
		return fmt.Errorf("postgres proxy: listen %s: %w", p.cfg.Listen, err)
	}
	p.listener = ln
	go p.accept()
	return nil
}

func (p *postgresProxy) accept() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *postgresProxy) handle(client net.Conn) {
	defer client.Close()

	// Read client's first message; may be SSLRequest (80877103) or StartupMessage (196608).
	startup, err := pgReadStartup(client)
	if err != nil {
		p.log.Error("postgres proxy: read client startup", "err", err)
		return
	}

	// SSLRequest: respond with 'N' and re-read the real StartupMessage.
	if len(startup) == 4 && binary.BigEndian.Uint32(startup) == 80877103 {
		if _, err := client.Write([]byte{'N'}); err != nil {
			p.log.Error("postgres proxy: send ssl reject", "err", err)
			return
		}
		startup, err = pgReadStartup(client)
		if err != nil {
			p.log.Error("postgres proxy: read client startup after ssl reject", "err", err)
			return
		}
	}

	if len(startup) < 4 {
		p.log.Error("postgres proxy: startup too short")
		return
	}
	proto := binary.BigEndian.Uint32(startup)
	if proto != 196608 {
		p.log.Error("postgres proxy: unexpected protocol version", "proto", proto)
		return
	}

	// Parse client params to extract database (if config doesn't override).
	clientParams := pgParseParams(startup[4:])
	db := p.cfg.Database
	if db == "" {
		db = clientParams["database"]
	}

	upstream, err := net.Dial("tcp", p.cfg.Upstream)
	if err != nil {
		p.log.Error("postgres proxy: upstream dial failed", "upstream", p.cfg.Upstream, "err", err)
		return
	}
	defer upstream.Close()

	// Send our own StartupMessage to upstream with config credentials.
	ourStartup := pgBuildStartup(p.cfg.User, db)
	if err := pgWriteStartup(upstream, ourStartup); err != nil {
		p.log.Error("postgres proxy: write startup to upstream", "err", err)
		return
	}

	// Auth exchange loop: upstream may send multiple auth messages before OK.
	for {
		msg, err := pgReadMessage(upstream)
		if err != nil {
			p.log.Error("postgres proxy: read upstream auth message", "err", err)
			return
		}

		switch msg[0] {
		case 'R': // Authentication
			authType := binary.BigEndian.Uint32(msg[1:5])
			switch authType {
			case 0: // AuthenticationOK — done
				// Forward OK to client (client didn't authenticate with us, but it
				// expects to see the OK so the startup phase completes on its side).
				if err := pgWriteMessage(client, msg); err != nil {
					p.log.Error("postgres proxy: write auth ok to client", "err", err)
					return
				}
				// Read remaining startup messages until ReadyForQuery.
				if err := p.forwardStartup(upstream, client); err != nil {
					p.log.Error("postgres proxy: forward startup", "err", err)
				}
				return

			case 5: // AuthenticationMD5Password
				if len(msg) < 9 {
					p.log.Error("postgres proxy: MD5 auth message too short")
					return
				}
				salt := msg[5:9]
				resp := pgMD5Password(p.cfg.User, p.cfg.Password, salt)
				reply := pgBuildPasswordMessage(resp)
				if err := pgWriteMessage(upstream, reply); err != nil {
					p.log.Error("postgres proxy: send MD5 response", "err", err)
					return
				}

			case 10: // AuthenticationSASL — SCRAM-SHA-256
				mechanisms := pgParseSASLMechanisms(msg[5:])
				supported := false
				for _, m := range mechanisms {
					if m == "SCRAM-SHA-256" {
						supported = true
						break
					}
				}
				if !supported {
					p.log.Error("postgres proxy: upstream offered no supported SASL mechanism", "mechanisms", mechanisms)
					return
				}
				if err := p.doSCRAM(upstream, p.cfg.Password); err != nil {
					p.log.Error("postgres proxy: SCRAM auth failed", "err", err)
					return
				}
				// After SCRAM completes (server-final verified), loop back to read next R message.

			case 11: // AuthenticationSASLContinue — handled inside doSCRAM
				p.log.Error("postgres proxy: unexpected SASLContinue outside SCRAM handler")
				return

			case 12: // AuthenticationSASLFinal — handled inside doSCRAM
				p.log.Error("postgres proxy: unexpected SASLFinal outside SCRAM handler")
				return

			default:
				p.log.Error("postgres proxy: unsupported auth type", "type", authType)
				return
			}

		case 'E': // ErrorResponse
			p.log.Error("postgres proxy: upstream auth error", "msg", pgParseError(msg))
			return

		default:
			p.log.Error("postgres proxy: unexpected message during auth", "type", string(msg[0]))
			return
		}
	}
}

// forwardStartup reads ParameterStatus / BackendKeyData / ReadyForQuery from upstream
// and forwards them to the client, then enters the bidirectional pipe.
func (p *postgresProxy) forwardStartup(upstream, client net.Conn) error {
	for {
		msg, err := pgReadMessage(upstream)
		if err != nil {
			return fmt.Errorf("read startup message: %w", err)
		}
		if err := pgWriteMessage(client, msg); err != nil {
			return fmt.Errorf("write startup message to client: %w", err)
		}
		if msg[0] == 'Z' { // ReadyForQuery
			p.log.Info("postgres proxy: client connected", "upstream", p.cfg.Upstream)
			pipe(client, upstream)
			return nil
		}
	}
}

// doSCRAM performs the SCRAM-SHA-256 exchange against upstream.
// It starts after the server has sent AuthenticationSASL (type 10).
func (p *postgresProxy) doSCRAM(upstream net.Conn, password string) error {
	// --- client-first ---
	clientNonce := make([]byte, 18)
	if _, err := rand.Read(clientNonce); err != nil {
		return fmt.Errorf("generate nonce: %w", err)
	}
	cnonce := base64.StdEncoding.EncodeToString(clientNonce)

	clientFirstBare := "n=,r=" + cnonce
	clientFirst := "n,," + clientFirstBare

	// SASLInitialResponse: mechanism + client-first
	saslInit := pgBuildSASLInitialResponse("SCRAM-SHA-256", []byte(clientFirst))
	if err := pgWriteMessage(upstream, saslInit); err != nil {
		return fmt.Errorf("write SASLInitialResponse: %w", err)
	}

	// --- server-first (AuthenticationSASLContinue, type 11) ---
	msg, err := pgReadMessage(upstream)
	if err != nil {
		return fmt.Errorf("read server-first: %w", err)
	}
	if msg[0] != 'R' || binary.BigEndian.Uint32(msg[1:5]) != 11 {
		return fmt.Errorf("expected SASLContinue, got type=%c authtype=%d", msg[0], binary.BigEndian.Uint32(msg[1:5]))
	}
	serverFirst := string(msg[5:])

	// Parse server-first: r=<snonce>, s=<salt>, i=<iterations>
	sf := pgParseSCRAMServerFirst(serverFirst)
	if sf == nil {
		return fmt.Errorf("malformed server-first: %q", serverFirst)
	}
	if !strings.HasPrefix(sf["r"], cnonce) {
		return fmt.Errorf("server nonce does not begin with client nonce")
	}

	salt, err := base64.StdEncoding.DecodeString(sf["s"])
	if err != nil {
		return fmt.Errorf("decode salt: %w", err)
	}
	iterations := 0
	fmt.Sscanf(sf["i"], "%d", &iterations)
	if iterations < 1 {
		return fmt.Errorf("invalid iteration count: %s", sf["i"])
	}

	// Derive keys per RFC 5802.
	saltedPassword := pgPBKDF2([]byte(password), salt, iterations, 32)
	clientKey := pgHMAC(saltedPassword, "Client Key")
	storedKey := sha256.Sum256(clientKey)
	serverKey := pgHMAC(saltedPassword, "Server Key")

	// client-final-message-without-proof
	channelBinding := base64.StdEncoding.EncodeToString([]byte("n,,"))
	clientFinalWithoutProof := "c=" + channelBinding + ",r=" + sf["r"]

	// AuthMessage = client-first-bare + "," + server-first + "," + client-final-without-proof
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof

	clientSignature := pgHMAC(storedKey[:], authMessage)
	clientProof := make([]byte, 32)
	for i := range clientProof {
		clientProof[i] = clientKey[i] ^ clientSignature[i]
	}

	clientFinal := clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)

	saslResponse := pgBuildSASLResponse([]byte(clientFinal))
	if err := pgWriteMessage(upstream, saslResponse); err != nil {
		return fmt.Errorf("write SASLResponse: %w", err)
	}

	// --- server-final (AuthenticationSASLFinal, type 12) ---
	msg, err = pgReadMessage(upstream)
	if err != nil {
		return fmt.Errorf("read server-final: %w", err)
	}
	if msg[0] != 'R' || binary.BigEndian.Uint32(msg[1:5]) != 12 {
		return fmt.Errorf("expected SASLFinal, got type=%c authtype=%d", msg[0], binary.BigEndian.Uint32(msg[1:5]))
	}
	serverFinal := string(msg[5:])

	// Verify server signature.
	expectedServerSig := base64.StdEncoding.EncodeToString(pgHMAC(serverKey, authMessage))
	sf2 := pgParseSCRAMServerFirst(serverFinal) // reuse k=v parser
	if sf2["v"] != expectedServerSig {
		return fmt.Errorf("server signature mismatch")
	}

	return nil
}

func (p *postgresProxy) Stop(_ context.Context) error {
	if p.listener == nil {
		return nil
	}
	return p.listener.Close()
}

// --- wire helpers ---

// pgReadStartup reads the startup packet (no type byte, just 4-byte length + body).
func pgReadStartup(r io.Reader) ([]byte, error) {
	var length uint32
	if err := binary.Read(r, binary.BigEndian, &length); err != nil {
		return nil, err
	}
	if length < 4 {
		return nil, fmt.Errorf("startup length %d too small", length)
	}
	body := make([]byte, length-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return body, nil
}

// pgWriteStartup writes a startup packet (length-prefixed, no type byte).
func pgWriteStartup(w io.Writer, payload []byte) error {
	length := uint32(len(payload) + 4)
	if err := binary.Write(w, binary.BigEndian, length); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// pgReadMessage reads a regular message: 1-byte type + 4-byte length (includes itself) + body.
func pgReadMessage(r io.Reader) ([]byte, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	length := int(binary.BigEndian.Uint32(hdr[1:])) - 4
	if length < 0 {
		return nil, fmt.Errorf("message length %d too small", length+4)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	msg := make([]byte, 1+length)
	msg[0] = hdr[0]
	copy(msg[1:], body)
	return msg, nil
}

// pgWriteMessage writes a regular message (type + 4-byte length + body).
// msg[0] is the type byte; the rest is the body.
func pgWriteMessage(w io.Writer, msg []byte) error {
	hdr := make([]byte, 5)
	hdr[0] = msg[0]
	binary.BigEndian.PutUint32(hdr[1:], uint32(len(msg)-1+4))
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(msg[1:])
	return err
}

// pgBuildStartup builds a StartupMessage payload (without the outer length prefix).
func pgBuildStartup(user, database string) []byte {
	var b []byte
	// Protocol 3.0
	b = binary.BigEndian.AppendUint32(b, 196608)
	b = append(b, []byte("user\x00")...)
	b = append(b, []byte(user+"\x00")...)
	if database != "" {
		b = append(b, []byte("database\x00")...)
		b = append(b, []byte(database+"\x00")...)
	}
	b = append(b, 0) // terminator
	return b
}

// pgParseParams parses the null-terminated key=value pairs in a StartupMessage body
// (after the 4-byte protocol version word).
func pgParseParams(data []byte) map[string]string {
	params := make(map[string]string)
	for len(data) > 0 {
		end := 0
		for end < len(data) && data[end] != 0 {
			end++
		}
		if end == 0 {
			break
		}
		key := string(data[:end])
		data = data[end+1:]
		end = 0
		for end < len(data) && data[end] != 0 {
			end++
		}
		val := string(data[:end])
		data = data[end+1:]
		params[key] = val
	}
	return params
}

// pgBuildPasswordMessage builds a PasswordMessage (type 'p').
func pgBuildPasswordMessage(password string) []byte {
	msg := make([]byte, 1+len(password)+1)
	msg[0] = 'p'
	copy(msg[1:], password)
	// null terminator already zero
	return msg
}

// pgMD5Password computes the MD5 password response: "md5" + md5(md5(password+user)+salt).
func pgMD5Password(user, password string, salt []byte) string {
	h1 := md5.Sum([]byte(password + user))
	hex1 := fmt.Sprintf("%x", h1)
	h2 := md5.Sum(append([]byte(hex1), salt...))
	return "md5" + fmt.Sprintf("%x", h2)
}

// pgParseSASLMechanisms parses the mechanism list from an AuthenticationSASL body.
// The body is a sequence of null-terminated strings terminated by an extra null.
func pgParseSASLMechanisms(data []byte) []string {
	var out []string
	for len(data) > 0 {
		end := 0
		for end < len(data) && data[end] != 0 {
			end++
		}
		if end == 0 {
			break
		}
		out = append(out, string(data[:end]))
		data = data[end+1:]
	}
	return out
}

// pgBuildSASLInitialResponse builds a SASLInitialResponse message (type 'p').
// Format: mechanism null int32(clientDataLen) clientData
func pgBuildSASLInitialResponse(mechanism string, clientData []byte) []byte {
	msg := []byte{'p'}
	msg = append(msg, []byte(mechanism)...)
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint32(msg, uint32(len(clientData)))
	msg = append(msg, clientData...)
	return msg
}

// pgBuildSASLResponse builds a SASLResponse message (type 'p').
func pgBuildSASLResponse(data []byte) []byte {
	msg := []byte{'p'}
	msg = append(msg, data...)
	return msg
}

// pgParseSCRAMServerFirst parses a comma-separated k=v string (server-first or server-final).
func pgParseSCRAMServerFirst(s string) map[string]string {
	out := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		if idx := strings.IndexByte(part, '='); idx > 0 {
			out[part[:idx]] = part[idx+1:]
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// pgHMAC computes HMAC-SHA-256(key, message).
func pgHMAC(key []byte, message string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(message))
	return mac.Sum(nil)
}

// pgPBKDF2 is a minimal PBKDF2-HMAC-SHA256 implementation (RFC 2898) to avoid
// an external dependency for the single use in SCRAM-SHA-256.
func pgPBKDF2(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	out := make([]byte, numBlocks*hashLen)
	buf := make([]byte, 4)
	for block := 1; block <= numBlocks; block++ {
		binary.BigEndian.PutUint32(buf, uint32(block))
		prf.Reset()
		prf.Write(salt)
		prf.Write(buf)
		U := prf.Sum(nil)
		T := make([]byte, hashLen)
		copy(T, U)
		for n := 1; n < iter; n++ {
			prf.Reset()
			prf.Write(U)
			U = prf.Sum(nil)
			for i := range T {
				T[i] ^= U[i]
			}
		}
		copy(out[(block-1)*hashLen:], T)
	}
	return out[:keyLen]
}

// pgParseError extracts the human-readable message from an ErrorResponse.
func pgParseError(msg []byte) string {
	// msg[0] is 'E'; body is a sequence of field-type byte + null-terminated string.
	body := msg[1:]
	for len(body) > 0 {
		fieldType := body[0]
		body = body[1:]
		end := 0
		for end < len(body) && body[end] != 0 {
			end++
		}
		val := string(body[:end])
		body = body[end+1:]
		if fieldType == 'M' { // Message
			return val
		}
	}
	return "(unknown error)"
}
