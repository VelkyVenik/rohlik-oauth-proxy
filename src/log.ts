function ts(): string {
  return new Date().toISOString();
}

export function log(event: string, details?: Record<string, unknown>) {
  const parts = [ts(), event];
  if (details) {
    const safe = Object.entries(details)
      .map(([k, v]) => `${k}=${v}`)
      .join(" ");
    parts.push(safe);
  }
  console.log(parts.join(" | "));
}

export function logWarn(event: string, details?: Record<string, unknown>) {
  const parts = [ts(), "WARN", event];
  if (details) {
    const safe = Object.entries(details)
      .map(([k, v]) => `${k}=${v}`)
      .join(" ");
    parts.push(safe);
  }
  console.warn(parts.join(" | "));
}

export function logError(event: string, details?: Record<string, unknown>) {
  const parts = [ts(), "ERROR", event];
  if (details) {
    const safe = Object.entries(details)
      .map(([k, v]) => `${k}=${v}`)
      .join(" ");
    parts.push(safe);
  }
  console.error(parts.join(" | "));
}
