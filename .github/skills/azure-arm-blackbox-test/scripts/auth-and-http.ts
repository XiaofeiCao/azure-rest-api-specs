import { execFileSync } from "node:child_process";
import type { ExchangeStep, OwnedTargetResource, WireHttpExchange } from "./types.ts";

export const DISPOSABLE_RG_PREFIX = "rg-arm-blackbox-";
export const DEFAULT_ARM_BASE_URL = "https://management.azure.com";

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

const cachedArmTokens = new Map<string, CachedToken>();

export interface TokenProviderOptions {
  explicitToken?: string;
  subscriptionId?: string;
  armBaseUrl?: string;
  tokenResource?: string;
}

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]", "::1"]);

/**
 * Validates and normalizes a user-supplied ARM / Canary / Dogfood base URL.
 * Requires HTTPS except when explicitly targeting a local loopback mock server (`http://127.0.0.1` / `localhost`).
 */
export function validateAndNormalizeArmBaseUrl(rawBaseUrl?: string): string {
  const candidate =
    rawBaseUrl?.trim() || process.env.ARM_BLACKBOX_BASE_URL?.trim() || DEFAULT_ARM_BASE_URL;
  let parsed: URL;
  try {
    parsed = new URL(candidate);
  } catch {
    throw new Error(`Invalid ARM base URL "${candidate}": expected an absolute https:// URL.`);
  }
  if (parsed.username || parsed.password) {
    throw new Error(`Invalid ARM base URL "${parsed.origin}": embedded credentials are forbidden.`);
  }
  if (parsed.search || parsed.hash) {
    throw new Error(
      `Invalid ARM base URL "${candidate}": query strings and URL fragments are not permitted.`,
    );
  }
  const isLoopbackHttp =
    parsed.protocol === "http:" && LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase());
  if (parsed.protocol !== "https:" && !isLoopbackHttp) {
    throw new Error(
      `Invalid ARM base URL "${candidate}": HTTPS is required for non-loopback ARM/Canary endpoints.`,
    );
  }
  const cleanPath = parsed.pathname.replace(/\/+$/, "");
  return `${parsed.origin}${cleanPath}`;
}

export function validateAndNormalizeAllowedArmOrigins(
  origins?: string[],
  allowLoopbackHttp = false,
): string[] {
  if (!origins || origins.length === 0) {
    return [];
  }
  const normalized = new Set<string>();
  for (const raw of origins) {
    const trimmed = raw.trim();
    if (!trimmed) {
      continue;
    }
    let parsed: URL;
    try {
      parsed = new URL(trimmed);
    } catch {
      throw new Error(`Invalid allowed ARM origin "${trimmed}": expected an https:// origin.`);
    }
    if (parsed.username || parsed.password) {
      throw new Error(
        `Invalid allowed ARM origin "${parsed.origin}": embedded credentials are forbidden.`,
      );
    }
    if ((parsed.pathname && parsed.pathname !== "/") || parsed.search || parsed.hash) {
      throw new Error(
        `Invalid allowed ARM origin "${trimmed}": specify origin only (e.g. "https://management.azure.com") without path, query, or hash.`,
      );
    }
    const isLoopback =
      allowLoopbackHttp &&
      parsed.protocol === "http:" &&
      LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase());
    if (parsed.protocol !== "https:" && !isLoopback) {
      throw new Error(`Invalid allowed ARM origin "${trimmed}": HTTPS is required.`);
    }
    normalized.add(parsed.origin.toLowerCase());
  }
  return [...normalized].sort();
}

/**
 * Infers the Entra ID token resource audience for public Azure, regional EUAP/Canary, Dogfood, or Sovereign clouds.
 */
export function inferArmTokenResource(armBaseUrl?: string, explicitTokenResource?: string): string {
  const override = explicitTokenResource?.trim() || process.env.ARM_BLACKBOX_TOKEN_RESOURCE?.trim();
  if (override) {
    return override;
  }
  if (!armBaseUrl) {
    return DEFAULT_ARM_BASE_URL;
  }
  const host = new URL(validateAndNormalizeArmBaseUrl(armBaseUrl)).hostname.toLowerCase();
  if (
    host === "api-dogfood.resources.windows-int.net" ||
    host.endsWith(".resources.windows-int.net")
  ) {
    return "https://management.core.windows.net/";
  }
  if (host === "management.usgovcloudapi.net" || host.endsWith(".usgovcloudapi.net")) {
    return "https://management.usgovcloudapi.net";
  }
  if (host === "management.chinacloudapi.cn" || host.endsWith(".chinacloudapi.cn")) {
    return "https://management.chinacloudapi.cn";
  }
  if (host === "management.microsoftazure.de" || host.endsWith(".microsoftazure.de")) {
    return "https://management.microsoftazure.de";
  }
  return DEFAULT_ARM_BASE_URL;
}

/**
 * Resolves a relative ARM path or absolute URL against `armBaseUrl` without duplicating any configured base path prefix.
 */
export function resolveArmRelativeOrAbsoluteUrl(armBaseUrl: string, pathOrUrl: string): string {
  if (/^https?:\/\//i.test(pathOrUrl)) {
    return pathOrUrl;
  }
  const normalizedBase = validateAndNormalizeArmBaseUrl(armBaseUrl);
  const baseObj = new URL(normalizedBase);
  const basePrefix = baseObj.pathname.replace(/\/+$/, "");
  const cleanRel = pathOrUrl.startsWith("/") ? pathOrUrl : `/${pathOrUrl}`;
  if (
    basePrefix &&
    (cleanRel.toLowerCase() === basePrefix.toLowerCase() ||
      cleanRel.toLowerCase().startsWith(`${basePrefix.toLowerCase()}/`))
  ) {
    return `${baseObj.origin}${cleanRel}`;
  }
  return `${normalizedBase}${cleanRel}`;
}

/**
 * Strips any configured `armBaseUrl` pathname prefix (e.g. `/arm-canary`) from a URL's pathname
 * when the URL targets the configured base origin, yielding the canonical `/subscriptions/...` path.
 */
export function stripConfiguredArmBasePath(targetUrl: string, trustedArmBaseUrl?: string): string {
  const parsedTarget = /^https?:\/\//i.test(targetUrl)
    ? new URL(targetUrl)
    : new URL(targetUrl.startsWith("/") ? targetUrl : `/${targetUrl}`, DEFAULT_ARM_BASE_URL);
  const rawPathname = decodeURIComponent(parsedTarget.pathname);
  if (!trustedArmBaseUrl) {
    return rawPathname;
  }
  try {
    const expectedBase = new URL(validateAndNormalizeArmBaseUrl(trustedArmBaseUrl));
    const basePrefix = expectedBase.pathname.replace(/\/+$/, "");
    if (basePrefix && parsedTarget.origin.toLowerCase() === expectedBase.origin.toLowerCase()) {
      if (rawPathname.toLowerCase() === basePrefix.toLowerCase()) {
        return "/";
      }
      if (rawPathname.toLowerCase().startsWith(`${basePrefix.toLowerCase()}/`)) {
        return rawPathname.slice(basePrefix.length);
      }
    }
  } catch {
    // Fall back to raw decoded pathname if base URL cannot be parsed.
  }
  return rawPathname;
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
  const tokenResource = inferArmTokenResource(options?.armBaseUrl, options?.tokenResource);
  const cacheKey = `${(options?.subscriptionId ?? "default").toLowerCase()}::${tokenResource.toLowerCase()}`;
  const now = Date.now();
  const cached = cachedArmTokens.get(cacheKey);
  if (cached && cached.expiresAtMs - now > 120_000) {
    return cached.accessToken;
  }

  const args = ["account", "get-access-token", "--resource", tokenResource, "-o", "json"];
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
    throw new Error(`Azure CLI did not return an accessToken for ${tokenResource}.`);
  }

  const expiresAtMs =
    parsed.expires_on !== undefined
      ? Number(parsed.expires_on) * 1000
      : parsed.expiresOn
        ? Date.parse(parsed.expiresOn)
        : now + 15 * 60_000;

  cachedArmTokens.set(cacheKey, {
    accessToken: parsed.accessToken,
    expiresAtMs: Number.isFinite(expiresAtMs) ? expiresAtMs : now + 15 * 60_000,
  });
  return parsed.accessToken;
}

export function isValidDisposableRgName(rgName: string): boolean {
  return (
    rgName.toLowerCase().startsWith(DISPOSABLE_RG_PREFIX) &&
    /^rg-arm-blackbox-[a-z0-9-]+$/i.test(rgName)
  );
}

export interface SafetyGuardContext {
  trustedArmBaseUrl?: string;
  allowedArmOrigins?: string[];
  subscriptionId?: string;
  disposableRgName?: string;
  ownedTargetResources?: OwnedTargetResource[];
  allowDisposableRgLifecycle?: boolean;
}

function inferCanonicalSameCloudArmOrigin(expectedBase: URL): string | undefined {
  if (expectedBase.protocol !== "https:") {
    return undefined;
  }
  const host = expectedBase.hostname.toLowerCase();
  if (/^[a-z0-9-]+\.management\.azure\.com$/i.test(host)) {
    return "https://management.azure.com";
  }
  if (/^[a-z0-9-]+\.api-dogfood\.resources\.windows-int\.net$/i.test(host)) {
    return "https://api-dogfood.resources.windows-int.net";
  }
  if (/^[a-z0-9-]+\.management\.usgovcloudapi\.net$/i.test(host)) {
    return "https://management.usgovcloudapi.net";
  }
  if (/^[a-z0-9-]+\.management\.chinacloudapi\.cn$/i.test(host)) {
    return "https://management.chinacloudapi.cn";
  }
  return undefined;
}

/**
 * Validates that a target URL matches the configured trusted ARM/Canary origin (or its same-cloud canonical ARM polling origin)
 * and uses HTTPS (allowing loopback HTTP only when trustedArmBaseUrl itself is explicitly configured to loopback).
 */
export function assertTrustedArmOrigin(
  targetUrl: string,
  trustedArmBaseUrl?: string,
  allowedArmOrigins?: string[],
): URL {
  const parsed = new URL(targetUrl);
  if (parsed.username || parsed.password) {
    throw new Error(`Blocked request with embedded URL credentials: ${parsed.origin}`);
  }

  const expectedBase = new URL(validateAndNormalizeArmBaseUrl(trustedArmBaseUrl));
  const isExplicitLoopbackBase =
    expectedBase.protocol === "http:" && LOOPBACK_HOSTS.has(expectedBase.hostname.toLowerCase());
  const isTargetLoopbackHttp =
    isExplicitLoopbackBase &&
    parsed.protocol === "http:" &&
    LOOPBACK_HOSTS.has(parsed.hostname.toLowerCase());

  if (parsed.protocol !== "https:" && !isTargetLoopbackHttp) {
    throw new Error(
      `Blocked insecure transport "${parsed.protocol}" for ARM target "${parsed.origin}": HTTPS is required.`,
    );
  }

  const permittedOrigins = new Set<string>([expectedBase.origin.toLowerCase()]);
  const canonicalParent = inferCanonicalSameCloudArmOrigin(expectedBase);
  if (canonicalParent) {
    permittedOrigins.add(canonicalParent.toLowerCase());
  }
  for (const extra of validateAndNormalizeAllowedArmOrigins(
    allowedArmOrigins,
    isExplicitLoopbackBase,
  )) {
    permittedOrigins.add(extra);
  }

  if (!permittedOrigins.has(parsed.origin.toLowerCase())) {
    throw new Error(
      `Blocked request to untrusted origin "${parsed.origin}": requests carrying ARM Bearer tokens must match [${[...permittedOrigins].join(", ")}].`,
    );
  }

  return parsed;
}

const CROSS_SCOPE_BODY_KEY_RE =
  /^(targetresourcegroup|targetsubscriptionid|destinationresourceid|targetresourceid|destinationcontainer|targetid|movedresourceid|privatelinkserviceid|remoteprivatelinkserviceid)$/i;

export function parseRetryAfterMs(headers: Record<string, string>, fallbackMs: number): number {
  const raw = headers["retry-after"]?.trim();
  if (!raw) {
    return fallbackMs;
  }
  const seconds = Number(raw);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return seconds === 0 ? Math.min(fallbackMs, 250) : Math.round(seconds * 1000);
  }
  const parsedDateMs = Date.parse(raw);
  if (Number.isFinite(parsedDateMs)) {
    return Math.max(0, parsedDateMs - Date.now());
  }
  return fallbackMs;
}

function assertNoCrossScopeBodyTargets(
  body: unknown,
  ctx: SafetyGuardContext,
  ancestors = new Set<object>(),
): void {
  if (!body || typeof body !== "object") {
    return;
  }
  if (ancestors.has(body)) {
    return;
  }
  const nextAncestors = new Set(ancestors);
  nextAncestors.add(body);

  if (Array.isArray(body)) {
    for (const item of body) {
      assertNoCrossScopeBodyTargets(item, ctx, nextAncestors);
    }
    return;
  }

  const expectedSub = ctx.subscriptionId?.toLowerCase();
  const expectedRg = ctx.disposableRgName?.toLowerCase();

  for (const [key, val] of Object.entries(body as Record<string, unknown>)) {
    if (typeof val === "string" && CROSS_SCOPE_BODY_KEY_RE.test(key)) {
      const lowerKey = key.toLowerCase();
      if (lowerKey === "targetsubscriptionid") {
        if (!expectedSub || val.trim().toLowerCase() !== expectedSub) {
          throw new Error(
            `Blocked cross-scope mutation field "${key}" targeting subscription "${val}" (expected "${ctx.subscriptionId ?? "<unset>"}").`,
          );
        }
      } else {
        const subMatch = /\/subscriptions\/([^/]+)/i.exec(val);
        const rgMatch = /\/resourcegroups\/([^/]+)/i.exec(val);
        if (subMatch && expectedSub && subMatch[1].toLowerCase() !== expectedSub) {
          throw new Error(
            `Blocked cross-scope mutation field "${key}" targeting subscription "${subMatch[1]}" (expected "${ctx.subscriptionId}").`,
          );
        }
        if (rgMatch) {
          if (!expectedRg || rgMatch[1].toLowerCase() !== expectedRg) {
            throw new Error(
              `Blocked cross-scope mutation field "${key}" targeting Resource Group "${rgMatch[1]}" outside "${ctx.disposableRgName ?? "<unset>"}".`,
            );
          }
        } else if (lowerKey === "targetresourcegroup") {
          if (!expectedRg || val.trim().toLowerCase() !== expectedRg) {
            throw new Error(
              `Blocked cross-scope mutation field "${key}" targeting Resource Group "${val}" outside "${ctx.disposableRgName ?? "<unset>"}".`,
            );
          }
        }
      }
    } else if (val && typeof val === "object") {
      assertNoCrossScopeBodyTargets(val, ctx, nextAncestors);
    }
  }
}

/**
 * Enforces hard-coded origin, subscription, and write protection so ARM requests
 * never leak tokens off-origin or mutate resources outside the session's disposable test Resource Group.
 */
export function assertSafeArmTarget(
  method: string,
  targetUrl: string,
  ctx: SafetyGuardContext,
  requestBody?: unknown,
): void {
  assertTrustedArmOrigin(targetUrl, ctx.trustedArmBaseUrl, ctx.allowedArmOrigins);
  const upperMethod = method.toUpperCase();
  if (upperMethod === "GET" || upperMethod === "HEAD" || upperMethod === "OPTIONS") {
    return;
  }

  assertNoCrossScopeBodyTargets(requestBody, ctx);

  const pathname = stripConfiguredArmBasePath(targetUrl, ctx.trustedArmBaseUrl).replace(/\/+$/, "");
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

  // Operations scoped to a Resource Provider inside the disposable RG (rejects RG-level cross-scope actions such as /moveResources: #3904).
  const rgScopedMatch = /^\/subscriptions\/[^/]+\/resourcegroups\/([^/]+)\/providers\/.+$/i.exec(
    pathname,
  );
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
  assertSafeArmTarget(options.method, options.url, options.safetyContext, options.body);

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
