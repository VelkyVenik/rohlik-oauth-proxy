import { hashToken } from "./store";
import { validateTokenFormat } from "./security";

export async function resolveToken(
  authHeader: string | null
): Promise<string | null> {
  if (!authHeader?.startsWith("Bearer ")) return null;
  const token = authHeader.slice(7);
  if (!validateTokenFormat(token)) return null;
  return hashToken(token);
}
