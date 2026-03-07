import { chmodSync } from "node:fs";
import { Database } from "bun:sqlite";

let db: Database;

export function initDB() {
  db = new Database("proxy.db", { create: true });
  db.run("PRAGMA journal_mode=WAL");
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      token_hash TEXT UNIQUE NOT NULL,
      rohlik_email_enc TEXT NOT NULL,
      rohlik_pass_enc TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS oauth_clients (
      client_id TEXT PRIMARY KEY,
      client_secret_hash TEXT NOT NULL,
      redirect_uris TEXT NOT NULL,
      client_name TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.run(`
    CREATE TABLE IF NOT EXISTS oauth_codes (
      code_hash TEXT PRIMARY KEY,
      client_id TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      code_challenge TEXT,
      code_challenge_method TEXT,
      rohlik_email_enc TEXT NOT NULL,
      rohlik_pass_enc TEXT NOT NULL,
      expires_at INTEGER NOT NULL,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  // Restrict DB file permissions after full initialization
  for (const f of ["proxy.db", "proxy.db-wal", "proxy.db-shm"]) {
    try { chmodSync(f, 0o600); } catch {}
  }
}

let _keyPromise: Promise<Buffer> | null = null;
function getKeyOnce(): Promise<Buffer> {
  if (!_keyPromise) {
    const secret = process.env.PROXY_SECRET;
    if (!secret) throw new Error("PROXY_SECRET not set");
    if (secret.length < 32)
      throw new Error("PROXY_SECRET must be at least 32 characters");
    _keyPromise = crypto.subtle
      .digest("SHA-256", new TextEncoder().encode(secret))
      .then((buf) => Buffer.from(new Uint8Array(buf)));
  }
  return _keyPromise;
}

let _cryptoKeyPromise: Promise<CryptoKey> | null = null;
function getCryptoKey(): Promise<CryptoKey> {
  if (!_cryptoKeyPromise) {
    _cryptoKeyPromise = getKeyOnce().then((key) =>
      crypto.subtle.importKey("raw", new Uint8Array(key), { name: "AES-GCM" }, false, [
        "encrypt",
        "decrypt",
      ])
    );
  }
  return _cryptoKeyPromise;
}

async function encrypt(plaintext: string): Promise<string> {
  const cryptoKey = await getCryptoKey();
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipherBuf = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    new TextEncoder().encode(plaintext)
  );
  const cipher = Buffer.from(new Uint8Array(cipherBuf));
  // AES-GCM appends 16-byte auth tag
  const authTag = cipher.subarray(cipher.length - 16);
  const encrypted = cipher.subarray(0, cipher.length - 16);
  return [
    Buffer.from(iv).toString("hex"),
    encrypted.toString("hex"),
    authTag.toString("hex"),
  ].join(":");
}

async function decrypt(data: string): Promise<string> {
  const [ivHex, encHex, tagHex] = data.split(":");
  const iv = Buffer.from(ivHex, "hex");
  const encrypted = Buffer.from(encHex, "hex");
  const authTag = Buffer.from(tagHex, "hex");
  const cryptoKey = await getCryptoKey();
  // Combine encrypted + authTag for WebCrypto
  const combined = Buffer.concat([encrypted, authTag]);
  const plainBuf = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    combined
  );
  return new TextDecoder().decode(plainBuf);
}

export async function hashToken(token: string): Promise<string> {
  const buf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(token)
  );
  return Buffer.from(new Uint8Array(buf)).toString("hex");
}

export async function createUser(
  email: string,
  rohlikEmail: string,
  rohlikPass: string,
  tokenHash: string
): Promise<void> {
  const encEmail = await encrypt(rohlikEmail);
  const encPass = await encrypt(rohlikPass);
  db.run(
    "INSERT INTO users (email, token_hash, rohlik_email_enc, rohlik_pass_enc) VALUES (?, ?, ?, ?)",
    [email, tokenHash, encEmail, encPass]
  );
}

export async function getUserByTokenHash(
  tokenHash: string
): Promise<{ rohlikEmail: string; rohlikPass: string } | null> {
  const row = db
    .query(
      "SELECT rohlik_email_enc, rohlik_pass_enc FROM users WHERE token_hash = ?"
    )
    .get(tokenHash) as {
    rohlik_email_enc: string;
    rohlik_pass_enc: string;
  } | null;
  if (!row) return null;
  return {
    rohlikEmail: await decrypt(row.rohlik_email_enc),
    rohlikPass: await decrypt(row.rohlik_pass_enc),
  };
}

export function deleteByEmailHash(emailHash: string): boolean {
  const result = db.run("DELETE FROM users WHERE email = ?", [emailHash]);
  return result.changes > 0;
}

export function deleteById(id: number): boolean {
  const result = db.run("DELETE FROM users WHERE id = ?", [id]);
  return result.changes > 0;
}

export async function listUsers(): Promise<
  { id: number; rohlikEmail: string; createdAt: string }[]
> {
  const rows = db
    .query("SELECT id, rohlik_email_enc, created_at FROM users ORDER BY id")
    .all() as { id: number; rohlik_email_enc: string; created_at: string }[];
  return Promise.all(
    rows.map(async (row) => ({
      id: row.id,
      rohlikEmail: await decrypt(row.rohlik_email_enc),
      createdAt: row.created_at,
    }))
  );
}

// --- OAuth ---

export async function createOAuthClient(
  clientId: string,
  clientSecretHash: string,
  redirectUris: string[],
  clientName?: string
): Promise<void> {
  db.run(
    "INSERT INTO oauth_clients (client_id, client_secret_hash, redirect_uris, client_name) VALUES (?, ?, ?, ?)",
    [clientId, clientSecretHash, JSON.stringify(redirectUris), clientName || null]
  );
}

export function getOAuthClient(
  clientId: string
): { clientSecretHash: string; redirectUris: string[] } | null {
  const row = db
    .query("SELECT client_secret_hash, redirect_uris FROM oauth_clients WHERE client_id = ?")
    .get(clientId) as { client_secret_hash: string; redirect_uris: string } | null;
  if (!row) return null;
  return {
    clientSecretHash: row.client_secret_hash,
    redirectUris: JSON.parse(row.redirect_uris),
  };
}

export async function createOAuthCode(
  codeHash: string,
  clientId: string,
  redirectUri: string,
  codeChallenge: string | null,
  codeChallengeMethod: string | null,
  rohlikEmail: string,
  rohlikPass: string
): Promise<void> {
  const encEmail = await encrypt(rohlikEmail);
  const encPass = await encrypt(rohlikPass);
  const expiresAt = Date.now() + 10 * 60 * 1000; // 10 minutes
  db.run(
    `INSERT INTO oauth_codes (code_hash, client_id, redirect_uri, code_challenge, code_challenge_method, rohlik_email_enc, rohlik_pass_enc, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
    [codeHash, clientId, redirectUri, codeChallenge, codeChallengeMethod, encEmail, encPass, expiresAt]
  );
}

export async function consumeOAuthCode(
  codeHash: string
): Promise<{
  clientId: string;
  redirectUri: string;
  codeChallenge: string | null;
  codeChallengeMethod: string | null;
  rohlikEmail: string;
  rohlikPass: string;
} | null> {
  const row = db
    .query(
      "SELECT client_id, redirect_uri, code_challenge, code_challenge_method, rohlik_email_enc, rohlik_pass_enc, expires_at FROM oauth_codes WHERE code_hash = ?"
    )
    .get(codeHash) as {
    client_id: string;
    redirect_uri: string;
    code_challenge: string | null;
    code_challenge_method: string | null;
    rohlik_email_enc: string;
    rohlik_pass_enc: string;
    expires_at: number;
  } | null;
  if (!row) return null;
  // Delete the code (one-time use)
  db.run("DELETE FROM oauth_codes WHERE code_hash = ?", [codeHash]);
  // Check expiry
  if (Date.now() > row.expires_at) return null;
  return {
    clientId: row.client_id,
    redirectUri: row.redirect_uri,
    codeChallenge: row.code_challenge,
    codeChallengeMethod: row.code_challenge_method,
    rohlikEmail: await decrypt(row.rohlik_email_enc),
    rohlikPass: await decrypt(row.rohlik_pass_enc),
  };
}

export function cleanupExpiredCodes(): void {
  db.run("DELETE FROM oauth_codes WHERE expires_at < ?", [Date.now()]);
}

