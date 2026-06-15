# credential-gateway

A local proxy that holds all credentials in a root-only config file outside any worktree. Clients connect to local endpoints with no credentials; the gateway injects real credentials before forwarding to upstream services.

```
app/agent
  ├─ HTTP  → localhost:8080/openai/...   → api.openai.com        (Bearer injected)
  ├─ MySQL → localhost:3307 (no passwd)  → real MySQL            (credentials injected)
  └─ Redis → localhost:6380 (no auth)    → real Redis            (AUTH injected)
```

No `.env` files. No credentials in the worktree at all.

## Setup

1. Copy `config.example.yaml` to `~/.config/credential-gateway/config.yaml`
2. Fill in your credentials
3. Lock the file: `chmod 0600 ~/.config/credential-gateway/config.yaml`
4. Run: `credential-gateway` (or `credential-gateway -config /path/to/config.yaml`)

The gateway refuses to start if the config file is group- or world-readable.

## Build

```
go build -o credential-gateway .
```

## Config locations (searched in order)

- `~/.config/credential-gateway/config.yaml`
- `/etc/credential-gateway/config.yaml`
