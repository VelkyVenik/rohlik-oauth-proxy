const MAX_BODY_SIZE = 1_048_576; // 1MB
const MAX_KEYS = 100_000;

// Sliding window rate limiter
const windows = new Map<string, number[]>();

function rateLimit(
  key: string,
  maxRequests: number,
  windowMs: number
): boolean {
  const now = Date.now();
  let timestamps = windows.get(key);
  if (!timestamps) {
    if (windows.size >= MAX_KEYS) {
      // Delete the oldest entry (first key in insertion order)
      const oldest = windows.keys().next().value;
      if (oldest !== undefined) windows.delete(oldest);
    }
    timestamps = [];
    windows.set(key, timestamps);
  }
  // Remove expired entries
  while (timestamps.length > 0 && timestamps[0] <= now - windowMs) {
    timestamps.shift();
  }
  if (timestamps.length >= maxRequests) return false;
  timestamps.push(now);
  return true;
}

export function checkTokenRate(token: string): boolean {
  return rateLimit(`tok:${token}`, 60, 60_000); // 60 req/min
}

export function checkUnauthRate(ip: string): boolean {
  return rateLimit(`unauth:${ip}`, 30, 60_000); // 30 req/min
}

export function checkOAuthRate(ip: string): boolean {
  return rateLimit(`oauth:${ip}`, 20, 60_000); // 20 req/min
}

export function validateEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 254;
}

export function validatePassword(password: string): boolean {
  return typeof password === "string" && password.length > 0 && password.length <= 1000;
}

export function validateTokenFormat(token: string): boolean {
  return /^[a-f0-9]{64}$/.test(token);
}

export async function readBodyWithLimit(
  req: Request,
  maxSize: number = MAX_BODY_SIZE
): Promise<string | null> {
  if (!req.body) return "";
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalSize = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      totalSize += value.byteLength;
      if (totalSize > maxSize) {
        reader.cancel();
        return null;
      }
      chunks.push(value);
    }
  } catch {
    return null;
  }
  const merged = new Uint8Array(totalSize);
  let offset = 0;
  for (const chunk of chunks) {
    merged.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(merged);
}

export function securityHeaders(): Record<string, string> {
  return {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "X-XSS-Protection": "1; mode=block",
    "Referrer-Policy": "no-referrer",
    "Content-Security-Policy":
      "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
  };
}

export function validateSessionId(id: string): boolean {
  return /^[a-zA-Z0-9_-]{1,256}$/.test(id);
}

export function corsHeaders(): Record<string, string> {
  return {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, Mcp-Session-Id, Accept",
    "Access-Control-Expose-Headers": "Mcp-Session-Id",
  };
}

// Periodically clean up old rate limit entries
setInterval(() => {
  const now = Date.now();
  for (const [key, timestamps] of windows) {
    while (timestamps.length > 0 && timestamps[0] <= now - 3_600_000) {
      timestamps.shift();
    }
    if (timestamps.length === 0) windows.delete(key);
  }
}, 60_000);
