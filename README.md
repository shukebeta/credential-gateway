# credential-gateway

**A local credential injection proxy for development.** credential-gateway sits between your app and upstream services, holding all credentials in a single root-owned config file outside every worktree. Your app connects to localhost with no credentials; the gateway injects them before forwarding.

```
app / agent
  ├─ HTTP       → localhost:8080/openai/…   → api.openai.com      (Authorization header injected)
  ├─ MySQL      → localhost:3307 (no passwd) → real MySQL         (credentials injected at handshake)
  ├─ Redis      → localhost:6380 (no auth)   → real Redis         (AUTH command injected)
  ├─ PostgreSQL → localhost:5433 (no passwd) → real PostgreSQL    (MD5 / SCRAM-SHA-256 injected)
  └─ Oracle     → localhost:1522 (no passwd) → real Oracle DB     (TNS/TTC auth injected)
```

It solves three problems that `.env` files and secrets managers don't:

- **Credentials leak into worktrees** — `.env` files get committed, shared, or left behind in old branches
- **Per-project setup overhead** — every new worktree or teammate needs the same credentials wired up again
- **Rotating a key means touching every project** — rotate once in `config.yaml`, nothing else changes

One config file. One process. All projects on the machine share it.

## Prerequisites

- Go 1.22+

No other runtime dependencies. The binary uses only the standard library plus `gopkg.in/yaml.v3` for config parsing.

## Build

```bash
go build -o credential-gateway .
```

## Setup

```bash
mkdir -p ~/.config/credential-gateway
cp config.example.yaml ~/.config/credential-gateway/config.yaml
$EDITOR ~/.config/credential-gateway/config.yaml   # fill in real credentials
chmod 0600 ~/.config/credential-gateway/config.yaml
./credential-gateway
```

The gateway refuses to start if the config file is group- or world-readable. This is enforced at startup, not just advisory.

## Config

Config is YAML. All five proxy types are optional — include only the services you need. Multiple entries per section are supported.

```yaml
# HTTP reverse proxy — injects arbitrary headers
http:
  - name: openai
    listen: "127.0.0.1:8080"
    upstream: "https://api.openai.com"
    headers:
      Authorization: "Bearer sk-…"

# MySQL proxy — injects user/password/database at handshake
mysql:
  - listen: "127.0.0.1:3307"
    upstream: "real-db-host:3306"
    user: dbuser
    password: "…"
    database: mydb

# Redis proxy — sends AUTH before piping client traffic
redis:
  - listen: "127.0.0.1:6380"
    upstream: "real-redis-host:6379"
    password: "…"

# PostgreSQL proxy — supports MD5 and SCRAM-SHA-256 auth
postgres:
  - listen: "127.0.0.1:5433"
    upstream: "real-pg-host:5432"
    user: dbuser
    password: "…"
    database: mydb   # optional; falls through to client's requested database if omitted

# Oracle proxy — TNS wire protocol with TTC O3LOG/O3AUTH credential injection
oracle:
  - listen: "127.0.0.1:1522"
    upstream: "real-oracle-host:1521"
    user: appuser
    password: "…"
    service: ORCLPDB1   # Oracle service name in the TNS connect descriptor
```

**Config search order** (first found wins):

1. `~/.config/credential-gateway/config.yaml`
2. `/etc/credential-gateway/config.yaml`
3. Custom path: `credential-gateway -config /path/to/config.yaml`

## Running

```bash
credential-gateway                              # use default config search path
credential-gateway -config ~/my-config.yaml    # explicit path
```

Logs are written to stderr in JSON format (`log/slog`). Shutdown is graceful: send `SIGINT` or `SIGTERM` and all listeners drain within 10 seconds.

## Architecture

```
main.go
  └─ Gateway
       ├─ []HTTPListener       (net/http/httputil.ReverseProxy, header injection via Director)
       ├─ []MySQLListener      (raw TCP, credentials injected at MySQL native auth handshake)
       ├─ []RedisListener      (raw TCP, AUTH command prepended before client traffic)
       ├─ []PostgreSQLListener (raw TCP, MD5 password or SCRAM-SHA-256 exchange handled)
       └─ []OracleListener     (raw TCP, TNS CONNECT + TTC O3LOG/O3AUTH exchange)
```

Each listener implements `Start() / Stop()`. `Gateway.Start()` launches all of them concurrently; `Gateway.Stop(ctx)` shuts them down in parallel with the provided deadline.

**Protocol depth per proxy:**

| Proxy | What the gateway handles |
|---|---|
| HTTP | Header injection via `Director`; streaming and chunked transfer preserved |
| MySQL | Full native auth handshake; client sends no password |
| Redis | Pre-pipes `AUTH <password>` before forwarding client commands |
| PostgreSQL | SSLRequest negotiation (rejects SSL), MD5 password response, full SCRAM-SHA-256 (PBKDF2 + RFC 5802 proof) |
| Oracle | TNS CONNECT/ACCEPT, NS negotiation, TTC O3LOG/O3AUTH with SHA1-derived auth token |

**Security notes:**

- Config file permissions are validated at startup (`0600` required; group- or world-readable rejected)
- Credential values are never logged — the HTTP Director explicitly avoids logging injected headers
- Credentials live only in the protected config file, never in environment variables or worktree files

## Testing

```bash
go test ./...
```

Tests cover HTTP header injection, MySQL handshake, Redis AUTH injection, PostgreSQL MD5/SCRAM-SHA-256, and Oracle TNS/TTC flows.

## Project structure

```
credential-gateway/
├── main.go                        # entry point, signal handling, graceful shutdown
├── config.example.yaml            # annotated example config (no real credentials)
├── go.mod / go.sum
└── internal/
    ├── config/
    │   ├── config.go              # YAML loading, permission check
    │   └── config_test.go
    └── gateway/
        ├── gateway.go             # orchestrator, Start/Stop lifecycle
        ├── http.go                # HTTP reverse proxy
        ├── http_test.go
        ├── mysql.go               # MySQL TCP proxy
        ├── mysql_test.go
        ├── redis.go               # Redis TCP proxy + AUTH injection
        ├── redis_test.go
        ├── postgres.go            # PostgreSQL proxy (MD5 + SCRAM-SHA-256)
        ├── postgres_test.go
        ├── oracle.go              # Oracle proxy (TNS wire protocol)
        ├── oracle_test.go
        └── pipe.go                # bidirectional TCP pipe shared by all TCP proxies
```
