import { initDB, cleanupExpiredCodes } from "./store";
import { handleMcpPost, handleMcpGet, handleMcpDelete } from "./proxy";
import {
  handleMetadata,
  handleClientRegistration,
  handleAuthorize,
  handleAuthorizeSubmit,
  handleTokenExchange,
} from "./oauth";
import {
  securityHeaders,
  corsHeaders,
} from "./security";
import { log, logError } from "./log";

if (!process.env.PROXY_SECRET || process.env.PROXY_SECRET.length < 32) {
  console.error("PROXY_SECRET must be set and at least 32 characters");
  process.exit(1);
}

initDB();
cleanupExpiredCodes();

// Periodically clean up expired OAuth codes (every 5 minutes)
setInterval(() => cleanupExpiredCodes(), 5 * 60 * 1000);

const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${process.env.PORT || "3000"}`).replace(/\/+$/, "");
const OPERATOR_NAME = process.env.OPERATOR_NAME || "the operator";
const OPERATOR_EMAIL = process.env.OPERATOR_EMAIL || "";

const landingHTML = (await Bun.file(
  new URL("landing.html", import.meta.url).pathname
).text())
  .replace(/\{\{PUBLIC_URL\}\}/g, PUBLIC_URL)
  .replace(/\{\{OPERATOR_NAME\}\}/g, OPERATOR_NAME)
  .replace(/\{\{OPERATOR_EMAIL\}\}/g, OPERATOR_EMAIL);

const authorizeHTML = await Bun.file(
  new URL("authorize.html", import.meta.url).pathname
).text();

const PORT = parseInt(process.env.PORT || "3000", 10);

function addHeaders(response: Response, req: Request): Response {
  const headers = new Headers(response.headers);
  for (const [k, v] of Object.entries(securityHeaders())) {
    if (!headers.has(k)) headers.set(k, v);
  }
  for (const [k, v] of Object.entries(corsHeaders())) headers.set(k, v);
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

Bun.serve({
  port: PORT,
  async fetch(req, server) {
    const url = new URL(req.url);
    const method = req.method;

    // CORS preflight
    if (method === "OPTIONS") {
      return addHeaders(new Response(null, { status: 204 }), req);
    }

    const ip = server.requestIP(req)?.address ?? "unknown";

    let response: Response;

    try {
      if (url.pathname === "/" && method === "GET") {
        response = new Response(landingHTML, {
          headers: { "Content-Type": "text/html; charset=utf-8" },
        });
      } else if (url.pathname === "/.well-known/oauth-authorization-server" && method === "GET") {
        response = handleMetadata(PUBLIC_URL);
      } else if (url.pathname === "/oauth/register" && method === "POST") {
        response = await handleClientRegistration(req, ip);
      } else if (url.pathname === "/oauth/authorize" && method === "GET") {
        response = handleAuthorize(req, authorizeHTML);
      } else if (url.pathname === "/oauth/authorize" && method === "POST") {
        response = await handleAuthorizeSubmit(req, ip);
      } else if (url.pathname === "/oauth/token" && method === "POST") {
        response = await handleTokenExchange(req, ip);
      } else if (url.pathname === "/mcp" && method === "POST") {
        response = await handleMcpPost(req, ip);
      } else if (url.pathname === "/mcp" && method === "GET") {
        response = await handleMcpGet(req, ip);
      } else if (url.pathname === "/mcp" && method === "DELETE") {
        response = await handleMcpDelete(req, ip);
      } else {
        response = Response.json({ error: "Not found" }, { status: 404 });
      }
    } catch (err) {
      logError("unhandled", { error: err instanceof Error ? `${err.name}: ${err.message}` : "unknown" });
      response = Response.json(
        { error: "Internal server error" },
        { status: 500 }
      );
    }

    return addHeaders(response, req);
  },
});

log("server-started", { port: PORT });
