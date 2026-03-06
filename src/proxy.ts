import { getUserByTokenHash } from "./store";
import { resolveToken } from "./auth";
import {
  checkTokenRate,
  checkUnauthRate,
  readBodyWithLimit,
  validateSessionId,
} from "./security";
import { log, logWarn, logError } from "./log";

const ROHLIK_MCP_URL = process.env.ROHLIK_MCP_URL || "https://mcp.rohlik.cz/mcp";

async function authenticate(
  req: Request,
  ip: string
): Promise<
  | { rohlikEmail: string; rohlikPass: string; tokenHash: string }
  | Response
> {
  if (!checkUnauthRate(ip)) {
    logWarn("mcp-ip-rate-limited", { ip });
    return Response.json({ error: "Rate limit exceeded" }, { status: 429 });
  }
  const tokenHash = await resolveToken(req.headers.get("authorization"));
  if (!tokenHash) {
    logWarn("mcp-unauthorized", { ip });
    return Response.json({ error: "Unauthorized" }, { status: 401 });
  }
  if (!checkTokenRate(tokenHash)) {
    logWarn("mcp-token-rate-limited", { ip, token: tokenHash.slice(0, 8) + "..." });
    return Response.json({ error: "Rate limit exceeded" }, { status: 429 });
  }
  const user = await getUserByTokenHash(tokenHash);
  if (!user) {
    logWarn("mcp-invalid-token", { ip });
    return Response.json({ error: "Invalid token" }, { status: 401 });
  }
  return { ...user, tokenHash };
}

export async function handleMcpPost(req: Request, ip: string): Promise<Response> {
  const result = await authenticate(req, ip);
  if (result instanceof Response) return result;

  const body = await readBodyWithLimit(req);
  if (body === null) {
    logWarn("mcp-post-body-too-large", { ip });
    return Response.json({ error: "Request too large" }, { status: 413 });
  }

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "rhl-email": result.rohlikEmail,
    "rhl-pass": result.rohlikPass,
  };

  // Forward Accept header
  const accept = req.headers.get("accept");
  if (accept) headers["Accept"] = accept;

  // Forward Mcp-Session-Id
  const sessionId = req.headers.get("mcp-session-id");
  if (sessionId) {
    if (!validateSessionId(sessionId)) {
      return Response.json({ error: "Invalid session ID" }, { status: 400 });
    }
    headers["Mcp-Session-Id"] = sessionId;
  }

  let upstream: globalThis.Response;
  try {
    upstream = await fetch(ROHLIK_MCP_URL, {
      method: "POST",
      headers,
      body,
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "TimeoutError") {
      logError("mcp-post-timeout", { ip });
      return Response.json({ error: "Gateway timeout" }, { status: 504 });
    }
    logError("mcp-post-fetch-error", { ip, error: err instanceof Error ? err.message : "unknown" });
    throw err;
  }

  if (upstream.status >= 400) {
    logWarn("mcp-post-upstream-error", { ip, status: upstream.status });
  }

  const responseHeaders = new Headers();
  const contentType = upstream.headers.get("content-type");
  if (contentType) responseHeaders.set("Content-Type", contentType);

  const upstreamSessionId = upstream.headers.get("mcp-session-id");
  if (upstreamSessionId)
    responseHeaders.set("Mcp-Session-Id", upstreamSessionId);

  // Stream SSE responses
  if (contentType?.includes("text/event-stream") && upstream.body) {
    log("mcp-post-stream", { ip });
    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders,
    });
  }

  // Return JSON responses directly
  const responseBody = await upstream.text();
  return new Response(responseBody, {
    status: upstream.status,
    headers: responseHeaders,
  });
}

export async function handleMcpGet(req: Request, ip: string): Promise<Response> {
  const result = await authenticate(req, ip);
  if (result instanceof Response) return result;

  const headers: Record<string, string> = {
    Accept: "text/event-stream",
    "rhl-email": result.rohlikEmail,
    "rhl-pass": result.rohlikPass,
  };

  const sessionId = req.headers.get("mcp-session-id");
  if (sessionId) {
    if (!validateSessionId(sessionId)) {
      return Response.json({ error: "Invalid session ID" }, { status: 400 });
    }
    headers["Mcp-Session-Id"] = sessionId;
  }

  let upstream: globalThis.Response;
  try {
    upstream = await fetch(ROHLIK_MCP_URL, {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "TimeoutError") {
      logError("mcp-get-timeout", { ip });
      return Response.json({ error: "Gateway timeout" }, { status: 504 });
    }
    logError("mcp-get-fetch-error", { ip, error: err instanceof Error ? err.message : "unknown" });
    throw err;
  }

  if (upstream.status >= 400) {
    logWarn("mcp-get-upstream-error", { ip, status: upstream.status });
  } else {
    log("mcp-get-stream", { ip });
  }

  const responseHeaders = new Headers();
  const contentType = upstream.headers.get("content-type");
  if (contentType) responseHeaders.set("Content-Type", contentType);

  const upstreamSessionId = upstream.headers.get("mcp-session-id");
  if (upstreamSessionId)
    responseHeaders.set("Mcp-Session-Id", upstreamSessionId);

  if (upstream.body) {
    return new Response(upstream.body, {
      status: upstream.status,
      headers: responseHeaders,
    });
  }

  return new Response(null, {
    status: upstream.status,
    headers: responseHeaders,
  });
}

export async function handleMcpDelete(req: Request, ip: string): Promise<Response> {
  const result = await authenticate(req, ip);
  if (result instanceof Response) return result;

  const headers: Record<string, string> = {
    "rhl-email": result.rohlikEmail,
    "rhl-pass": result.rohlikPass,
  };

  const sessionId = req.headers.get("mcp-session-id");
  if (sessionId) {
    if (!validateSessionId(sessionId)) {
      return Response.json({ error: "Invalid session ID" }, { status: 400 });
    }
    headers["Mcp-Session-Id"] = sessionId;
  }

  let upstream: globalThis.Response;
  try {
    upstream = await fetch(ROHLIK_MCP_URL, {
      method: "DELETE",
      headers,
      signal: AbortSignal.timeout(30_000),
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "TimeoutError") {
      logError("mcp-delete-timeout", { ip });
      return Response.json({ error: "Gateway timeout" }, { status: 504 });
    }
    logError("mcp-delete-fetch-error", { ip, error: err instanceof Error ? err.message : "unknown" });
    throw err;
  }

  log("mcp-delete", { ip, status: upstream.status });
  return new Response(null, { status: upstream.status });
}
