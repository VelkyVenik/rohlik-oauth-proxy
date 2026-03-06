import crypto from "node:crypto";
import {
  hashToken,
  createOAuthClient,
  getOAuthClient,
  createOAuthCode,
  consumeOAuthCode,
  createUser,
  deleteByEmailHash,
  cleanupExpiredCodes,
} from "./store";
import { validateEmail, validatePassword, checkOAuthRate } from "./security";
import { log, logWarn } from "./log";

async function constantTimeEqual(a: string, b: string): Promise<boolean> {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  return crypto.timingSafeEqual(Buffer.from(ha), Buffer.from(hb));
}

// CSRF token store (short-lived, in-memory)
const csrfTokens = new Map<string, number>();
const CSRF_TTL = 10 * 60 * 1000; // 10 minutes

function generateCsrfToken(): string {
  const token = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
  csrfTokens.set(token, Date.now() + CSRF_TTL);
  return token;
}

function verifyCsrfToken(token: string): boolean {
  const expiry = csrfTokens.get(token);
  if (!expiry) return false;
  csrfTokens.delete(token);
  return Date.now() < expiry;
}

// Periodically clean expired CSRF tokens
setInterval(() => {
  const now = Date.now();
  for (const [token, expiry] of csrfTokens) {
    if (now >= expiry) csrfTokens.delete(token);
  }
}, 60_000);

export function handleMetadata(publicUrl: string): Response {
  return Response.json({
    issuer: publicUrl,
    authorization_endpoint: `${publicUrl}/oauth/authorize`,
    token_endpoint: `${publicUrl}/oauth/token`,
    registration_endpoint: `${publicUrl}/oauth/register`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code"],
    code_challenge_methods_supported: ["S256"],
    token_endpoint_auth_methods_supported: ["client_secret_post"],
  });
}

export async function handleClientRegistration(req: Request, ip: string): Promise<Response> {
  // Rate limit client registration to prevent abuse
  if (!checkOAuthRate(ip)) {
    logWarn("oauth-register-rate-limited", { ip });
    return Response.json({ error: "rate_limit_exceeded" }, { status: 429 });
  }

  let body: any;
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  const redirectUris: string[] = body.redirect_uris;
  if (!Array.isArray(redirectUris) || redirectUris.length === 0) {
    return Response.json({ error: "invalid_redirect_uri" }, { status: 400 });
  }

  // Validate redirect URIs
  for (const uri of redirectUris) {
    try {
      new URL(uri);
    } catch {
      return Response.json({ error: "invalid_redirect_uri" }, { status: 400 });
    }
  }

  const clientId = Buffer.from(crypto.getRandomValues(new Uint8Array(16))).toString("hex");
  const clientSecret = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
  const clientSecretHash = await hashToken(clientSecret);

  await createOAuthClient(clientId, clientSecretHash, redirectUris, body.client_name);

  log("oauth-client-registered", { clientId });

  return Response.json({
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: redirectUris,
    client_name: body.client_name || null,
  }, { status: 201 });
}

export function handleAuthorize(req: Request, authorizeHTML: string): Response {
  const url = new URL(req.url);
  const clientId = url.searchParams.get("client_id");
  const redirectUri = url.searchParams.get("redirect_uri");
  const state = url.searchParams.get("state");
  const codeChallenge = url.searchParams.get("code_challenge");
  const codeChallengeMethod = url.searchParams.get("code_challenge_method");
  const responseType = url.searchParams.get("response_type");

  if (responseType !== "code") {
    return Response.json({ error: "unsupported_response_type" }, { status: 400 });
  }
  if (!clientId || !redirectUri) {
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }

  const client = getOAuthClient(clientId);
  if (!client) {
    return Response.json({ error: "invalid_client" }, { status: 400 });
  }
  if (!client.redirectUris.includes(redirectUri)) {
    return Response.json({ error: "invalid_redirect_uri" }, { status: 400 });
  }

  // Generate CSRF token
  const csrfToken = generateCsrfToken();

  // Render the login form with params embedded
  const html = authorizeHTML
    .replace(/\{\{CLIENT_ID\}\}/g, escapeHtml(clientId))
    .replace(/\{\{REDIRECT_URI\}\}/g, escapeHtml(redirectUri))
    .replace(/\{\{STATE\}\}/g, escapeHtml(state || ""))
    .replace(/\{\{CODE_CHALLENGE\}\}/g, escapeHtml(codeChallenge || ""))
    .replace(/\{\{CODE_CHALLENGE_METHOD\}\}/g, escapeHtml(codeChallengeMethod || ""))
    .replace(/\{\{CSRF_TOKEN\}\}/g, escapeHtml(csrfToken));

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy":
        "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
    },
  });
}

export async function handleAuthorizeSubmit(req: Request, ip: string): Promise<Response> {
  log("oauth-authorize-submit");

  if (!checkOAuthRate(ip)) {
    logWarn("oauth-authorize-rate-limited", { ip });
    return Response.json({ error: "Too many attempts. Please wait." }, { status: 429 });
  }

  const wantsJson = (req.headers.get("accept") || "").includes("application/json");

  let params: URLSearchParams;
  try {
    params = new URLSearchParams(await req.text());
  } catch (err) {
    logWarn("oauth-authorize-bad-form", { error: err instanceof Error ? err.message : "unknown" });
    return wantsJson
      ? Response.json({ error: "Could not parse form data." }, { status: 400 })
      : errorPage("Could not parse form data.");
  }

  const csrfParam = params.get("csrf_token") || "";
  if (!verifyCsrfToken(csrfParam)) {
    logWarn("oauth-authorize-csrf-failed", { ip });
    const msg = "Invalid or expired form. Please reload and try again.";
    return wantsJson ? Response.json({ error: msg }, { status: 403 }) : errorPage(msg);
  }

  const clientId = params.get("client_id") || "";
  const redirectUri = params.get("redirect_uri") || "";
  const state = params.get("state") || "";
  const codeChallenge = params.get("code_challenge") || null;
  const codeChallengeMethod = params.get("code_challenge_method") || null;
  const rohlikEmail = params.get("rohlik_email") || "";
  const rohlikPassword = params.get("rohlik_password") || "";

  if (!clientId || !redirectUri) {
    logWarn("oauth-authorize-missing-params", { hasClientId: !!clientId, hasRedirectUri: !!redirectUri });
    const msg = "Missing client_id or redirect_uri. Please start the connection from Claude.";
    return wantsJson ? Response.json({ error: msg }, { status: 400 }) : errorPage(msg);
  }

  const client = getOAuthClient(clientId);
  if (!client) {
    logWarn("oauth-authorize-unknown-client", { clientId });
    const msg = "Unknown client. Please reconnect from Claude.";
    return wantsJson ? Response.json({ error: msg }, { status: 400 }) : errorPage(msg);
  }
  if (!client.redirectUris.includes(redirectUri)) {
    logWarn("oauth-authorize-bad-redirect", { clientId, redirectUri });
    const msg = "Invalid redirect URI.";
    return wantsJson ? Response.json({ error: msg }, { status: 400 }) : errorPage(msg);
  }

  if (!rohlikEmail || !validateEmail(rohlikEmail)) {
    logWarn("oauth-authorize-invalid-email", { ip, clientId });
    const msg = "Please enter a valid email address.";
    return wantsJson ? Response.json({ error: msg }, { status: 400 }) : errorPage(msg);
  }
  if (!rohlikPassword || !validatePassword(rohlikPassword)) {
    logWarn("oauth-authorize-invalid-password", { ip, clientId });
    const msg = "Please enter your password.";
    return wantsJson ? Response.json({ error: msg }, { status: 400 }) : errorPage(msg);
  }

  // Generate auth code
  const code = Buffer.from(crypto.getRandomValues(new Uint8Array(32))).toString("hex");
  const codeHash = await hashToken(code);

  await createOAuthCode(
    codeHash,
    clientId,
    redirectUri,
    codeChallenge,
    codeChallengeMethod,
    rohlikEmail,
    rohlikPassword
  );

  log("oauth-authorize-ok", { clientId });

  // Build redirect URL with code
  const target = new URL(redirectUri);
  target.searchParams.set("code", code);
  if (state) target.searchParams.set("state", state);

  const redirectUrl = target.toString();
  log("oauth-authorize-redirect", { url: redirectUrl });

  // JSON response for JS-based form submission (webview-friendly)
  if (wantsJson) {
    return Response.json({ redirect_url: redirectUrl });
  }

  // 302 fallback for plain form submission
  return Response.redirect(redirectUrl, 302);
}

export async function handleTokenExchange(req: Request, ip: string): Promise<Response> {
  if (!checkOAuthRate(ip)) {
    return tokenError("rate_limit_exceeded");
  }

  // Cleanup expired codes opportunistically
  cleanupExpiredCodes();
  let params: URLSearchParams;
  const ct = req.headers.get("content-type") || "";
  if (ct.includes("application/x-www-form-urlencoded")) {
    params = new URLSearchParams(await req.text());
  } else if (ct.includes("application/json")) {
    const body = await req.json();
    params = new URLSearchParams(body);
  } else {
    params = new URLSearchParams(await req.text());
  }

  const grantType = params.get("grant_type");
  if (grantType !== "authorization_code") {
    return tokenError("unsupported_grant_type");
  }

  const code = params.get("code");
  const clientId = params.get("client_id");
  const clientSecret = params.get("client_secret");
  const redirectUri = params.get("redirect_uri");
  const codeVerifier = params.get("code_verifier");

  if (!code || !clientId || !clientSecret || !redirectUri) {
    return tokenError("invalid_request");
  }

  // Verify client
  const client = getOAuthClient(clientId);
  if (!client) {
    logWarn("oauth-token-invalid-client", { clientId });
    return tokenError("invalid_client");
  }

  // Verify client secret (required)
  const secretHash = await hashToken(clientSecret);
  if (secretHash !== client.clientSecretHash) {
    logWarn("oauth-token-bad-secret", { clientId });
    return tokenError("invalid_client");
  }

  // Consume auth code
  const codeHash = await hashToken(code);
  const codeData = await consumeOAuthCode(codeHash);
  if (!codeData) {
    logWarn("oauth-token-invalid-code", { clientId });
    return tokenError("invalid_grant");
  }

  if (codeData.clientId !== clientId || codeData.redirectUri !== redirectUri) {
    logWarn("oauth-token-mismatch", { clientId });
    return tokenError("invalid_grant");
  }

  // Verify PKCE
  if (codeData.codeChallenge) {
    if (!codeVerifier) {
      return tokenError("invalid_grant", "Code verifier required");
    }
    const digest = await crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(codeVerifier)
    );
    const computed = Buffer.from(new Uint8Array(digest))
      .toString("base64url");
    if (computed !== codeData.codeChallenge) {
      logWarn("oauth-token-pkce-failed", { clientId });
      return tokenError("invalid_grant", "PKCE verification failed");
    }
  }

  // Create access token and store user
  const tokenBytes = crypto.getRandomValues(new Uint8Array(32));
  const accessToken = Buffer.from(tokenBytes).toString("hex");
  const tokenHash = await hashToken(accessToken);
  const emailHash = await hashToken(codeData.rohlikEmail.toLowerCase());

  // Remove existing user for this email (re-login replaces old token)
  deleteByEmailHash(emailHash);
  await createUser(emailHash, codeData.rohlikEmail, codeData.rohlikPass, tokenHash);

  log("oauth-token-issued", { clientId });

  return Response.json({
    access_token: accessToken,
    token_type: "Bearer",
    expires_in: 365 * 24 * 3600, // 1 year
  });
}

function tokenError(error: string, description?: string): Response {
  const body: any = { error };
  if (description) body.error_description = description;
  return Response.json(body, { status: 400 });
}

function escapeHtml(s: string): string {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function errorPage(message: string): Response {
  const html = `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>Error</title>
<style>body{font-family:-apple-system,sans-serif;display:flex;justify-content:center;align-items:center;min-height:100vh;background:#f5f5f5;margin:0}
.card{background:#fff;border-radius:8px;padding:2rem;max-width:380px;box-shadow:0 2px 8px rgba(0,0,0,0.08);text-align:center}
h1{font-size:1.2rem;color:#991b1b;margin-bottom:0.5rem}p{color:#666;font-size:0.9rem}
a{color:#2563eb;display:inline-block;margin-top:1rem}</style></head>
<body><div class="card"><h1>Error</h1><p>${escapeHtml(message)}</p><a href="javascript:history.back()">Go back</a></div></body></html>`;
  return new Response(html, {
    status: 400,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}
