# CLAUDE.md

## Project overview

Rohlik MCP Proxy — a Bun-based HTTP server that proxies MCP (Model Context Protocol) requests from Claude to Rohlik's MCP server, handling OAuth 2.1 authentication and credential management.

## Tech stack

- **Runtime:** Bun (TypeScript, no transpilation step)
- **Database:** SQLite via `bun:sqlite` (file: `proxy.db`)
- **Crypto:** Web Crypto API (AES-256-GCM encryption, SHA-256 hashing)
- **Dependencies:** Zero runtime dependencies (only `bun-types` and `typescript` as dev deps)

## Commands

- `bun run start` — start server
- `bun run dev` — start with auto-reload
- `npx tsc --noEmit` — typecheck

## Architecture

```
Claude → /mcp (Bearer token) → Proxy → mcp.rohlik.cz/mcp (rhl-email/rhl-pass) → Rohlik
```

All routing is in `src/index.ts`. Request handling is split by concern:
- `oauth.ts` — OAuth 2.1 flow (client registration, authorize, token exchange)
- `proxy.ts` — MCP forwarding (POST/GET/DELETE with SSE streaming support)
- `auth.ts` — Bearer token resolution from Authorization header
- `store.ts` — SQLite schema, encryption/decryption, all DB operations
- `security.ts` — rate limiting, validation, headers
- `log.ts` — structured console logging

## Key conventions

- Never log credentials (email, password, tokens)
- All sensitive data encrypted with AES-256-GCM before DB storage
- Tokens stored as SHA-256 hashes, never plaintext
- Rate limiting is in-memory (sliding window), not persisted
- HTML templates use `{{PLACEHOLDER}}` pattern, replaced at serve time
- Security headers applied globally in `addHeaders()`, per-route CSP preserved via `if (!headers.has(k))`
- OAuth endpoints receive `ip` parameter for rate limiting
- CSRF tokens are in-memory, one-time use, 10 min TTL

## Environment variables

Required: `PROXY_SECRET` (min 32 chars)
Optional: `PORT` (default 3000), `PUBLIC_URL`, `ROHLIK_MCP_URL`, `OPERATOR_NAME`, `OPERATOR_EMAIL`

## Database tables

- `users` — id, email (hash), token_hash, rohlik_email_enc, rohlik_pass_enc, created_at
- `oauth_clients` — client_id, client_secret_hash, redirect_uris (JSON), client_name, created_at
- `oauth_codes` — code_hash, client_id, redirect_uri, code_challenge, rohlik_email_enc, rohlik_pass_enc, expires_at
