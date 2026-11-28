// Time-boxed approvals ("approve for N minutes"). They replace permanent
// always-allow rules: the broker cannot decrypt credentials without a
// passkey approval, so auto-approval reuses the DEK released by the approval
// that opened the window (the window's grant) until it expires.

import { ulid } from "ulid";

import { db } from "../db/client";

export const APPROVAL_WINDOW_MINUTES = [15, 60] as const;

// "endpoint": method + host + path, scoped to API key + requester IP.
// "provider": every request routed to the provider from the API key
// (advanced). Not IP-scoped: agents in cloud sandboxes, CI and VPNs egress
// from rotating IPs, and the requester IP comes from a client-influenced
// X-Forwarded-For, so it only caused re-prompts without adding protection.
export const APPROVAL_WINDOW_SCOPES = ["endpoint", "provider"] as const;
export type ApprovalWindowScope = (typeof APPROVAL_WINDOW_SCOPES)[number];

// Endpoint columns are NOT NULL; provider-scoped windows store this instead.
const ANY = "*";

function nowIso(): string {
  return new Date().toISOString();
}

export function getApprovalWindowScope(params: {
  apiKeyId: string;
  requesterIp: string;
  method: string;
  url: URL;
}): {
  apiKeyId: string;
  requesterIp: string;
  method: string;
  upstreamHost: string;
  upstreamPath: string;
} {
  // "Endpoint" means method + host + path (query is intentionally excluded).
  return {
    apiKeyId: params.apiKeyId,
    requesterIp: params.requesterIp,
    method: params.method.toUpperCase(),
    upstreamHost: params.url.hostname,
    upstreamPath: params.url.pathname || "/",
  };
}

export async function findActiveApprovalWindow(params: {
  userId: string;
  apiKeyId: string;
  // Null when the deployment does not pass a client IP; only provider-scoped
  // windows can match then.
  requesterIp: string | null;
  method: string;
  url: URL;
  providerId: string;
}): Promise<{
  id: string;
  grantId: string | null;
  expiresAt: string;
  scope: ApprovalWindowScope;
} | null> {
  const k = getApprovalWindowScope({
    ...params,
    requesterIp: params.requesterIp ?? "",
  });
  const now = nowIso();
  const database = await db();
  const row = (await database
    .query(
      // Only windows whose grant can still unlock a credential count: a
      // reconnect deletes the replaced credential's grants and a disconnect
      // revokes the account, and auto-approving against either would only
      // fail at execute (NO_GRANT) until the window expired.
      "SELECT w.id, w.grant_id, w.expires_at, w.scope FROM approval_windows w " +
        "JOIN credential_grants g ON g.id = w.grant_id AND g.user_id = w.user_id AND g.expires_at > ? " +
        "JOIN linked_accounts a ON a.id = g.linked_account_id AND a.status = 'active' " +
        "WHERE w.user_id = ? AND w.api_key_id = ? AND w.expires_at > ? AND ((w.scope = 'endpoint' AND w.requester_ip = ? AND w.method = ? AND w.upstream_host = ? AND w.upstream_path = ?) OR (w.scope = 'provider' AND w.provider_id = ?)) ORDER BY w.expires_at DESC LIMIT 1;"
    )
    .get(
      now,
      params.userId,
      k.apiKeyId,
      now,
      params.requesterIp,
      k.method,
      k.upstreamHost,
      k.upstreamPath,
      params.providerId
    )) as {
    id: string;
    grant_id: string | null;
    expires_at: string;
    scope: ApprovalWindowScope;
  } | null;

  return row
    ? {
        id: row.id,
        grantId: row.grant_id,
        expiresAt: row.expires_at,
        scope: row.scope,
      }
    : null;
}

export async function createApprovalWindow(params: {
  windowId?: string;
  userId: string;
  apiKeyId: string;
  // Required for endpoint windows; ignored for provider windows.
  requesterIp: string | null;
  method: string;
  url: URL;
  scope: ApprovalWindowScope;
  providerId: string | null;
  grantId: string | null;
  expiresAt: string;
}): Promise<{ windowId: string }> {
  if (params.scope === "provider" && !params.providerId) {
    throw new Error("provider-scoped approval window requires a provider id");
  }
  if (params.scope === "endpoint" && !params.requesterIp) {
    throw new Error("endpoint-scoped approval window requires a requester ip");
  }
  const endpoint = getApprovalWindowScope({
    ...params,
    requesterIp: params.requesterIp ?? ANY,
  });
  const k =
    params.scope === "provider"
      ? {
          ...endpoint,
          requesterIp: ANY,
          method: ANY,
          upstreamHost: ANY,
          upstreamPath: ANY,
        }
      : endpoint;
  const windowId = params.windowId ?? ulid();
  const database = await db();
  await database
    .query(
      "INSERT INTO approval_windows (id, user_id, api_key_id, requester_ip, method, upstream_host, upstream_path, scope, provider_id, grant_id, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);"
    )
    .run(
      windowId,
      params.userId,
      k.apiKeyId,
      k.requesterIp,
      k.method,
      k.upstreamHost,
      k.upstreamPath,
      params.scope,
      params.providerId,
      params.grantId,
      nowIso(),
      params.expiresAt
    );
  return { windowId };
}
