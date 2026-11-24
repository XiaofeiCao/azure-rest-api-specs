import { execFileSync } from "node:child_process";
import type { ExchangeStep, OwnedTargetResource, WireHttpExchange } from "./types.ts";

export const DISPOSABLE_RG_PREFIX = "rg-arm-blackbox-";

const SENSITIVE_HEADER_NAMES = new Set([
  "authorization",
  "proxy-authorization",
  "x-ms-authorization-auxiliary",
  "cookie",
  "set-cookie",
  "x-functions-key",
  "api-key",
  "ocp-apim-subscription-key",
]);

interface CachedToken {
  accessToken: string;
  expiresAtMs: number;
}

let cachedArmToken: CachedToken | undefined;

export interface TokenProviderOptions {
  explicitToken?: string;
  subscriptionId?: string;
}

function resolveAzExecutable(): string {
  return process.platform === "win32" ? "az.cmd" : "az";
}

export function getActiveAzSubscriptionId(): string {
  const envSub = process.env.AZURE_SUBSCRIPTION_ID?.trim();
  if (envSub) {
    return envSub;
  }
  const output = execFileSync(
    resolveAzExecutable(),
    ["account", "show", "--query", "id", "-o", "tsv"],
    {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      shell: process.platform === "win32",
    },
  ).trim();
  if (!output) {
    throw new Error(
      "Unable to determine active Azure subscription ID from `az account show`. Run `az login` or pass --subscription-id.",
    );
  }
  return output;
}

export function getArmBearerToken(options?: TokenProviderOptions): string {
  if (options?.explicitToken) {
    return options.explicitToken;
  }
  const envToken = process.env.ARM_BLACKBOX_ACCESS_TOKEN?.trim();
  if (envToken) {
    return envToken;
  }
  const now = Date.now();
  if (cachedArmToken && cachedArmToken.expiresAtMs - now > 120_000) {
    return cachedArmToken.accessToken;
  }

  const args = [
    "account",
    "get-access-token",
    "--resource",
    "https://management.azure.com",
    "-o",
    "json",
  ];
  if (options?.subscriptionId) {
    args.push("--subscription", options.subscriptionId);
  }

  const raw = execFileSync(resolveAzExecutable(), args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    shell: process.platform === "win32",
  });
  const parsed = JSON.parse(raw) as {
    accessToken?: string;
    expires_on?: number | string;
    expiresOn?: string;
  };
  if (!parsed.accessToken) {
    throw new Error("Azure CLI did not return an accessToken for https://management.azure.com.");
  }

  const expiresAtMs =
    parsed.expires_on !== undefined
      ? Number(parsed.expires_on) * 1000
      : parsed.expiresOn
        ? Date.parse(parsed.expiresOn)
        : now + 15 * 60_000;

  cachedArmToken = {
    accessToken: parsed.accessToken,
    expiresAtMs: Number.isFinite(expiresAtMs) ? expiresAtMs : now + 15 * 60_000,
  };
  return cachedArmToken.accessToken;
}

export function isValidDisposableRgName(rgName: string): boolean {
  return (
    rgName.toLowerCase().startsWith(DISPOSABLE_RG_PREFIX) &&
    /^rg-arm-blackbox-[a-z0-9-]+$/i.test(rgName)
  );
}

export interface SafetyGuardContext {
  trustedArmBaseUrl?: string;
  subscriptionId?: string;
  disposableRgName?: string;
  ownedTargetResources?: OwnedTargetResource[];
  allowDisposableRgLifecycle?: boolean;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

/**
 * Validates that a target URL matches the configured trusted ARM origin and uses HTTPS
 * (allowing loopback HTTP only when trustedArmBaseUrl itself is explicitly configured to that loopback origin).
 */
export function assertTrustedArmOrigin(targetUrl: string, trustedArmBaseUrl?: string): URL {
  const parsed = new URL(targetUrl);
  if (parsed.username || parsed.password) {
    throw new Error(`Blocked request with embedded URL credentials: ${parsed.origin}`);
  }

  const expectedBase = new URL(
    (trustedArmBaseUrl ?? "https://management.azure.com").replace(/\/+$/, ""),
  );
  if (parsed.origin.toLowerCase() !== expectedBase.origin.toLowerCase()) {
    throw new Error(
      `Blocked request to untrusted origin "${parsed.origin}": requests carrying ARM Bearer tokens must match "${expectedBase.origin}".`,
    );
  }

  const isExplicitLoopbackTest =
    expectedBase.protocol === "http:" &&
    LOOPBACK_HOSTS.has(expectedBase.hostname.toLowerCase()) &&
    LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase());

  if (parsed.protocol !== "https:" && !isExplicitLoopbackTest) {
    throw new Error(
      `Blocked insecure transport "${parsed.protocol}" for ARM target "${parsed.origin}": HTTPS is required.`,
    );
  }

  return parsed;
}

/**
 * Enforces hard-coded origin, subscription, and write protection so ARM requests
 * never leak tokens off-origin or mutate resources outside the session's disposable test Resource Group.
 */
export function assertSafeArmTarget(
  method: string,
  targetUrl: string,
  ctx: SafetyGuardContext,
): void {
  const parsed = assertTrustedArmOrigin(targetUrl, ctx.trustedArmBaseUrl);
  const upperMethod = method.toUpperCase();
  if (upperMethod === "GET" || upperMethod === "HEAD" || upperMethod === "OPTIONS") {
    return;
  }

  const pathname = decodeURIComponent(parsed.pathname).replace(/\/+$/, "");
  const subSegmentMatch = /^\/subscriptions\/([^/]+)(?:\/|$)/i.exec(pathname);

  // Non-destructive ARM name-availability checks are subscription/provider scoped POSTs.
  if (upperMethod === "POST" && /\/checknameavailability$/i.test(pathname)) {
    if (
      subSegmentMatch &&
      ctx.subscriptionId &&
      subSegmentMatch[1].toLowerCase() !== ctx.subscriptionId.toLowerCase()
    ) {
      throw new Error(
        `Blocked ${upperMethod} targeting subscription "${subSegmentMatch[1]}": expected "${ctx.subscriptionId}".`,
      );
    }
    return;
  }

  if (!ctx.subscriptionId) {
    throw new Error(
      `Blocked mutating ${upperMethod} request to ${pathname}: expected subscriptionId is missing from SafetyGuardContext.`,
    );
  }

  if (!subSegmentMatch || subSegmentMatch[1].toLowerCase() !== ctx.subscriptionId.toLowerCase()) {
    throw new Error(
      `Blocked mutating ${upperMethod} targeting subscription "${subSegmentMatch?.[1] ?? "<none>"}": mutations are strictly confined to subscription "${ctx.subscriptionId}".`,
    );
  }

  if (!ctx.disposableRgName) {
    throw new Error(
      `Blocked mutating ${upperMethod} request to ${pathname}: no disposable test Resource Group is registered in the ledger.`,
    );
  }

  if (!isValidDisposableRgName(ctx.disposableRgName)) {
    throw new Error(
      `Blocked mutating ${upperMethod} request: Resource Group "${ctx.disposableRgName}" does not have required "${DISPOSABLE_RG_PREFIX}" prefix.`,
    );
  }

  const rgLower = ctx.disposableRgName.toLowerCase();

  // Direct create/update/delete of the disposable RG itself (when manage-rg invokes it).
  const rgRootMatch = /^\/subscriptions\/[^/]+\/resourcegroups\/([^/]+)$/i.exec(pathname);
  if (rgRootMatch) {
    if (ctx.allowDisposableRgLifecycle && rgRootMatch[1].toLowerCase() === rgLower) {
      return;
    }
    throw new Error(
      `Blocked ${upperMethod} on Resource Group "${rgRootMatch[1]}": only lifecycle management of "${ctx.disposableRgName}" is permitted.`,
    );
  }

  // Operations scoped inside the disposable RG.
  const rgScopedMatch = /^\/subscriptions\/[^/]+\/resourcegroups\/([^/]+)\/.+$/i.exec(pathname);
  if (rgScopedMatch) {
    if (rgScopedMatch[1].toLowerCase() === rgLower) {
      return;
    }
    throw new Error(
      `Blocked mutating ${upperMethod} targeting Resource Group "${rgScopedMatch[1]}": mutations are strictly confined to "${ctx.disposableRgName}".`,
    );
  }

  // Subscription/location-scoped soft-delete purge/recover ONLY for recorded target-RP resource identities
  // matching providerNamespace, resource collection type, location, and name.
  const softDeleteMatch =
    /^\/subscriptions\/[^/]+\/providers\/([^/]+)\/locations\/([^/]+)\/deleted([^/]+)\/([^/]+)(?:\/purge)?$/i.exec(
      pathname,
    );
  if (softDeleteMatch && (upperMethod === "POST" || upperMethod === "DELETE")) {
    const [, urlProvider, urlLocation, deletedCollectionSuffix, targetName] = softDeleteMatch;
    const normProvider = urlProvider.toLowerCase();
    const normLoc = urlLocation.toLowerCase().replace(/\s+/g, "");
    const normCollection = deletedCollectionSuffix.toLowerCase();
    const normName = targetName.toLowerCase();

    const matchedOwned = (ctx.ownedTargetResources ?? []).some((res) => {
      if (res.providerNamespace.toLowerCase() !== normProvider) {
        return false;
      }
      if (res.collectionSegment.toLowerCase() !== normCollection) {
        return false;
      }
      if (res.name.toLowerCase() !== normName) {
        return false;
      }
      if (res.location && res.location.toLowerCase().replace(/\s+/g, "") !== normLoc) {
        return false;
      }
      if (res.resourceGroupName && res.resourceGroupName.toLowerCase() !== rgLower) {
        return false;
      }
      return true;
    });

    if (matchedOwned) {
      return;
    }
    throw new Error(
      `Blocked soft-delete ${upperMethod} on unowned resource "${urlProvider}/${deletedCollectionSuffix}/${targetName}" in "${urlLocation}": no matching target-RP resource identity is recorded for disposable RG "${ctx.disposableRgName}".`,
    );
  }

  throw new Error(
    `Blocked mutating ${upperMethod} request outside disposable Resource Group "${ctx.disposableRgName}": ${pathname}`,
  );
}

export function redactHeaders(
  headers: Record<string, string>,
  extraSensitiveNames?: Iterable<string>,
): Record<string, string> {
  const extraLower = new Set<string>();
  for (const name of extraSensitiveNames ?? []) {
    extraLower.add(name.toLowerCase());
  }
  const sanitized: Record<string, string> = {};
  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (SENSITIVE_HEADER_NAMES.has(lowerKey) || extraLower.has(lowerKey)) {
      sanitized[key] = "<redacted>";
    } else {
      sanitized[key] = value;
    }
  }
  return sanitized;
}

export interface SendRawRequestOptions {
  step: ExchangeStep;
  method: string;
  url: string;
  bearerToken: string;
  headers?: Record<string, string>;
  extraSensitiveHeaders?: string[];
  body?: unknown;
  safetyContext: SafetyGuardContext;
  timeoutMs?: number;
}

export async function sendRawHttpExchange(
  options: SendRawRequestOptions,
): Promise<WireHttpExchange> {
  assertSafeArmTarget(options.method, options.url, options.safetyContext);

  const requestHeaders: Record<string, string> = {
    Accept: "application/json",
    Authorization: `Bearer ${options.bearerToken}`,
    ...options.headers,
  };

  let serializedBody: string | undefined;
  if (options.body !== undefined) {
    const existingContentTypeEntry = Object.entries(requestHeaders).find(
      ([k]) => k.toLowerCase() === "content-type",
    );
    const effectiveContentType = existingContentTypeEntry?.[1] ?? "application/json";
    if (!existingContentTypeEntry) {
      requestHeaders["Content-Type"] = effectiveContentType;
    }
    const isJsonMediaType = /\bjson\b/i.test(effectiveContentType);
    serializedBody =
      typeof options.body === "string" && !isJsonMediaType
        ? options.body
        : JSON.stringify(options.body);
  }

  const startedAt = new Date();
  const startPerf = performance.now();
  const response = await fetch(options.url, {
    method: options.method.toUpperCase(),
    headers: requestHeaders,
    body: serializedBody,
    redirect: "manual",
    signal: AbortSignal.timeout(options.timeoutMs ?? 60_000),
  });
  const durationMs = Math.round(performance.now() - startPerf);

  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((val, key) => {
    responseHeaders[key.toLowerCase()] = val;
  });

  const rawText = await response.text();
  let parsedBody: unknown;
  let rawTextSnippet: string | undefined;
  if (rawText.length > 0) {
    try {
      parsedBody = JSON.parse(rawText);
    } catch {
      rawTextSnippet = rawText.slice(0, 1000);
    }
  }

  return {
    step: options.step,
    timestamp: startedAt.toISOString(),
    durationMs,
    request: {
      method: options.method.toUpperCase(),
      url: options.url,
      headers: redactHeaders(requestHeaders, options.extraSensitiveHeaders),
      ...(options.body !== undefined ? { body: options.body } : {}),
    },
    response: {
      status: response.status,
      headers: redactHeaders(responseHeaders, options.extraSensitiveHeaders),
      ...(parsedBody !== undefined ? { body: parsedBody } : {}),
      ...(rawTextSnippet !== undefined ? { rawTextSnippet } : {}),
    },
  };
}
