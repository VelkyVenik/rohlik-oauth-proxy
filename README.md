# Rohlik MCP Proxy

A proxy server that connects Claude (iOS, Android, Web, Desktop) to [Rohlik's MCP server](https://www.rohlik.cz/stranka/mcp-server).

Rohlik's MCP server requires custom `rhl-email`/`rhl-pass` headers that Claude can't set directly. This proxy bridges that gap — users sign in once via OAuth 2.1 and Claude handles the rest.

```
Claude  →  POST /mcp (Bearer token)  →  Proxy  →  POST mcp.rohlik.cz/mcp (rhl-email/rhl-pass)  →  Rohlik
```

## Requirements

- [Bun](https://bun.sh/) v1.0+

## Setup

```bash
# Clone and install
git clone <repo-url>
cd rohlik-mcp-proxy
bun install

# Configure
cp .env.example .env
# Edit .env with your values
```

### Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `PROXY_SECRET` | Yes | Encryption key for stored credentials (min 32 chars) |
| `PORT` | No | Server port (default: `3000`) |
| `PUBLIC_URL` | No | Public-facing URL (default: `http://localhost:3000`) |
| `ROHLIK_MCP_URL` | No | Rohlik MCP endpoint (default: `https://mcp.rohlik.cz/mcp`) |
| `OPERATOR_NAME` | No | Displayed on the landing page as the server operator |
| `OPERATOR_EMAIL` | No | Contact email displayed on the landing page |

## Running

```bash
# Production
bun run start

# Development (auto-reload)
bun run dev
```

## How it works

1. User adds `<PUBLIC_URL>/mcp` as a remote MCP server in Claude.
2. Claude initiates OAuth 2.1 (Authorization Code + PKCE):
   - Registers a client via `/oauth/register`
   - Opens the authorize page where the user enters Rohlik credentials
   - Exchanges the auth code for a Bearer token via `/oauth/token`
3. Claude sends MCP requests to `/mcp` with the Bearer token.
4. The proxy decrypts the stored Rohlik credentials and forwards requests to Rohlik's MCP server with the required headers.

## Security

- **Credentials encrypted at rest** — AES-256-GCM using `PROXY_SECRET`
- **Tokens hashed** — SHA-256, never stored in plaintext
- **OAuth 2.1 with PKCE** — S256 code challenge, one-time auth codes (10 min expiry)
- **CSRF protection** — one-time tokens on the authorize form
- **Rate limiting** — per-IP on OAuth endpoints (20/min), per-token on MCP (60/min), per-IP on unauthenticated requests (30/min)
- **Request size limit** — 1MB max body
- **Security headers** — CSP, HSTS, X-Frame-Options, X-Content-Type-Options
- **SQLite DB** — file permissions restricted to owner (600)

> **Warning:** Rohlik credentials (email + password) are stored encrypted on the server. They must be stored because Rohlik's MCP server requires them on every request. Only deploy this on infrastructure you control and trust.

## Project structure

```
src/
├── index.ts          # HTTP server, routing
├── oauth.ts          # OAuth 2.1 flow (metadata, registration, authorize, token)
├── proxy.ts          # MCP message forwarding to Rohlik
├── auth.ts           # Bearer token resolution
├── store.ts          # SQLite DB, encryption, user/client/code storage
├── security.ts       # Rate limiting, input validation, security headers
├── log.ts            # Structured console logging
├── landing.html      # Public landing page
└── authorize.html    # OAuth sign-in form
```

## API endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/` | — | Landing page |
| GET | `/.well-known/oauth-authorization-server` | — | OAuth metadata |
| POST | `/oauth/register` | — | Dynamic client registration |
| GET | `/oauth/authorize` | — | Authorize page (login form) |
| POST | `/oauth/authorize` | — | Submit credentials, get auth code |
| POST | `/oauth/token` | Client | Exchange auth code for access token |
| POST | `/mcp` | Bearer | Forward MCP request to Rohlik |
| GET | `/mcp` | Bearer | SSE stream from Rohlik |
| DELETE | `/mcp` | Bearer | Close MCP session |

## Author

Vaclav Slajs — [vaclav@slajs.eu](mailto:vaclav@slajs.eu)

## License

MIT
