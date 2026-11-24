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
 * WITHOUT decoding percent-encoded characters (`%25`, `%2F`) so downstream parameter extractors
 * decode each captured slot exactly once (#60789).
 */
export function stripConfiguredArmBasePath(targetUrl: string, trustedArmBaseUrl?: string): string {
  const parsedTarget = /^https?:\/\//i.test(targetUrl)
    ? new URL(targetUrl)
    : new URL(targetUrl.startsWith("/") ? targetUrl : `/${targetUrl}`, DEFAULT_ARM_BASE_URL);
  const rawPathname = parsedTarget.pathname;
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
    // Fall back to raw encoded pathname if base URL cannot be parsed.
  }
  return rawPathname;
}

export function findHeaderCaseInsensitive(
  headers: Record<string, string> | undefined,
  headerName: string,
): string | undefined {
  if (!headers) {
    return undefined;
  }
  if (headers[headerName] !== undefined) {
    return headers[headerName];
  }
  const lower = headerName.toLowerCase();
  if (headers[lower] !== undefined) {
    return headers[lower];
  }
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === lower) {
      return v;
    }
  }
  return undefined;
}

export function safeDecodeUriSegment(rawSegment: string): string {
  try {
    return decodeURIComponent(rawSegment);
  } catch {
    return rawSegment;
  }
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
  disposableRgCleanupStatus?: string;
  expectedRunId?: string;
  verifiedRgRunIdTag?: string;
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
  /^(?:targetresourcegroup|targetresourcegroupid|targetsubscriptionid|targetvirtualmachineid|targetdiskid|targetstorageaccountid|targetnetworkid|targetsubnetid|targetvnetid|destinationresourceid|destinationresourcegroupid|targetresourceid|destinationcontainer|targetid|movedresourceid|privatelinkserviceid|remoteprivatelinkserviceid|recoveryresourcegroupid|restoreresourcegroupid|(?:target|destination|restore|recovery|moved|remote)[a-z0-9_]*(?:resourcegroup|resourcegroupid|subscriptionid|resourceid|virtualmachineid|storageaccountid|subnetid|diskid|vnetid|networkid))$/i;

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
      if (lowerKey.endsWith("subscriptionid")) {
        if (!expectedSub || val.trim().toLowerCase() !== expectedSub) {
          throw new Error(
            `Blocked cross-scope mutation field "${key}" targeting subscription "${val}" (expected "${ctx.subscriptionId ?? "<unset>"}").`,
          );
        }
      } else {
        const subMatch = /\/subscriptions\/([^/]+)/i.exec(val);
        const rgMatch = /\/resourcegroups\/([^/]+)/i.exec(val);
        if (subMatch && (!expectedSub || subMatch[1].toLowerCase() !== expectedSub)) {
          throw new Error(
            `Blocked cross-scope mutation field "${key}" targeting subscription "${subMatch[1]}" (expected "${ctx.subscriptionId ?? "<unset>"}").`,
          );
        }
        if (rgMatch) {
          if (!expectedRg || rgMatch[1].toLowerCase() !== expectedRg) {
            throw new Error(
              `Blocked cross-scope mutation field "${key}" targeting Resource Group "${rgMatch[1]}" outside "${ctx.disposableRgName ?? "<unset>"}".`,
            );
          }
        } else if (lowerKey.endsWith("resourcegroup") || lowerKey.endsWith("resourcegroupid")) {
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

  const encodedPathname = stripConfiguredArmBasePath(targetUrl, ctx.trustedArmBaseUrl).replace(
    /\/+$/,
    "",
  );
  // Reject encoded path-separator smuggling (%2F / %5C) on mutating ARM targets.
  if (/%2f|%5c/i.test(encodedPathname)) {
    throw new Error(
      `Blocked mutating ${upperMethod} request containing percent-encoded path separators: ${encodedPathname}`,
    );
  }
  const pathname = encodedPathname
    .split("/")
    .map((seg) => safeDecodeUriSegment(seg))
    .join("/");
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

  if (!ctx.allowDisposableRgLifecycle) {
    if (ctx.disposableRgCleanupStatus !== undefined && ctx.disposableRgCleanupStatus !== "active") {
      throw new Error(
        `Blocked mutating ${upperMethod} request to ${pathname}: disposable Resource Group "${ctx.disposableRgName}" is not active (cleanupStatus="${ctx.disposableRgCleanupStatus}").`,
      );
    }
    if (ctx.expectedRunId !== undefined && ctx.verifiedRgRunIdTag !== ctx.expectedRunId) {
      throw new Error(
        `Blocked mutating ${upperMethod} request to ${pathname}: live Resource Group ownership tag "${ctx.verifiedRgRunIdTag ?? "<unverified>"}" does not match expected runId "${ctx.expectedRunId}".`,
      );
    }
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

  // Operations scoped to a Resource Provider inside the disposable RG (rejects RG-level cross-scope actions such as /moveResources
  // AND delegating Microsoft.Resources deployments/stacks/links that can target external RGs: #3904, #60636).
  const rgScopedMatch = /^\/subscriptions\/[^/]+\/resourcegroups\/([^/]+)\/providers\/(.+)$/i.exec(
    pathname,
  );
  if (rgScopedMatch) {
    if (rgScopedMatch[1].toLowerCase() !== rgLower) {
      throw new Error(
        `Blocked mutating ${upperMethod} targeting Resource Group "${rgScopedMatch[1]}": mutations are strictly confined to "${ctx.disposableRgName}".`,
      );
    }
    if (
      /^microsoft\.resources\/(?:deployments|deploymentstacks|templatespecs|links|deploymentscripts|tags)(?:\/|$)/i.test(
        rgScopedMatch[2],
      )
    ) {
      throw new Error(
        `Blocked Microsoft.Resources RG-level mutation "${rgScopedMatch[2]}": delegating deployments and direct RG tag overwrites are forbidden inside "${ctx.disposableRgName}".`,
      );
    }
    return;
  }

  // Subscription/location-scoped soft-delete purge/recover ONLY for recorded target-RP resource identities
  // matching subscriptionId, providerNamespace, resource collection type, location, and name (#51170).
  const softDeleteMatch =
    /^\/subscriptions\/([^/]+)\/providers\/([^/]+)\/locations\/([^/]+)\/deleted([^/]+)\/([^/]+)(?:\/purge)?$/i.exec(
      pathname,
    );
  if (softDeleteMatch && (upperMethod === "POST" || upperMethod === "DELETE")) {
    const [, urlSubId, urlProvider, urlLocation, deletedCollectionSuffix, targetName] =
      softDeleteMatch;
    const normSub = urlSubId.toLowerCase();
    const normProvider = urlProvider.toLowerCase();
    const normLoc = urlLocation.toLowerCase().replace(/\s+/g, "");
    const normCollection = deletedCollectionSuffix.toLowerCase();
    const normName = targetName.toLowerCase();

    const matchedOwned = (ctx.ownedTargetResources ?? []).some((res) => {
      const idSubMatch = /^\/subscriptions\/([^/]+)(?:\/|$)/i.exec(res.resourceId);
      const resSub = (res.subscriptionId ?? idSubMatch?.[1])?.toLowerCase();
      if (!resSub || resSub !== normSub) {
        return false;
      }
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
  onBeforeHeaderRedaction?: (unredacted: WireHttpExchange, redacted: WireHttpExchange) => void;
}

export async function sendRawHttpExchange(
  options: SendRawRequestOptions,
): Promise<WireHttpExchange> {
  assertSafeArmTarget(options.method, options.url, options.safetyContext, options.body);

  // Normalize request header keys via Fetch `Headers` so duplicate spellings combine consistently
  // and saved exchanges always expose lowercase header keys (#60839).
  const headerBag = new Headers();
  headerBag.set("accept", "application/json");
  headerBag.set("authorization", `Bearer ${options.bearerToken}`);
  for (const [k, v] of Object.entries(options.headers ?? {})) {
    headerBag.set(k, v);
  }

  let serializedBody: string | undefined;
  if (options.body !== undefined) {
    const effectiveContentType = headerBag.get("content-type") ?? "application/json";
    if (!headerBag.has("content-type")) {
      headerBag.set("content-type", effectiveContentType);
    }
    const isJsonMediaType = /\bjson\b/i.test(effectiveContentType);
    serializedBody =
      typeof options.body === "string" && !isJsonMediaType
        ? options.body
        : JSON.stringify(options.body);
  }

  const normalizedRequestHeaders: Record<string, string> = {};
  headerBag.forEach((val, key) => {
    normalizedRequestHeaders[key.toLowerCase()] = val;
  });

  const startedAt = new Date();
  const startPerf = performance.now();
  const response = await fetch(options.url, {
    method: options.method.toUpperCase(),
    headers: normalizedRequestHeaders,
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

  const timestamp = startedAt.toISOString();
  const redactedExchange: WireHttpExchange = {
    step: options.step,
    timestamp,
    durationMs,
    request: {
      method: options.method.toUpperCase(),
      url: options.url,
      headers: redactHeaders(normalizedRequestHeaders, options.extraSensitiveHeaders),
      ...(options.body !== undefined ? { body: options.body } : {}),
    },
    response: {
      status: response.status,
      headers: redactHeaders(responseHeaders, options.extraSensitiveHeaders),
      ...(parsedBody !== undefined ? { body: parsedBody } : {}),
      ...(rawTextSnippet !== undefined ? { rawTextSnippet } : {}),
    },
  };

  if (options.onBeforeHeaderRedaction) {
    // Strip only authentication credentials so @secret API headers can be validated in memory before persistence (#51340).
    const validationSafeReqHeaders = redactHeaders(normalizedRequestHeaders);
    const validationSafeRespHeaders = redactHeaders(responseHeaders);
    options.onBeforeHeaderRedaction(
      {
        step: options.step,
        timestamp,
        durationMs,
        request: {
          method: options.method.toUpperCase(),
          url: options.url,
          headers: validationSafeReqHeaders,
          ...(options.body !== undefined ? { body: options.body } : {}),
        },
        response: {
          status: response.status,
          headers: validationSafeRespHeaders,
          ...(parsedBody !== undefined ? { body: parsedBody } : {}),
          ...(rawTextSnippet !== undefined ? { rawTextSnippet } : {}),
        },
      },
      redactedExchange,
    );
  }

  return redactedExchange;
}

export const RUN_OWNERSHIP_TAG = "arm-blackbox-run-id";
const ARM_RESOURCES_TAG_CHECK_API_VERSION = "2024-03-01";

/**
 * Verifies against live ARM that the recorded disposable Resource Group exists and carries
 * the exact `arm-blackbox-run-id` tag for this ledger run before non-lifecycle mutations (#60602).
 */
export async function verifyLiveDisposableRgOwnership(options: {
  armBaseUrl: string;
  allowedArmOrigins?: string[];
  subscriptionId: string;
  rgName: string;
  expectedRunId: string;
  bearerToken: string;
}): Promise<string> {
  const rgCheckUrl = resolveArmRelativeOrAbsoluteUrl(
    options.armBaseUrl,
    `/subscriptions/${encodeURIComponent(options.subscriptionId)}/resourcegroups/${encodeURIComponent(options.rgName)}?api-version=${ARM_RESOURCES_TAG_CHECK_API_VERSION}`,
  );
  const check = await sendRawHttpExchange({
    step: "initial",
    method: "GET",
    url: rgCheckUrl,
    bearerToken: options.bearerToken,
    safetyContext: {
      trustedArmBaseUrl: options.armBaseUrl,
      allowedArmOrigins: options.allowedArmOrigins,
      subscriptionId: options.subscriptionId,
      disposableRgName: options.rgName,
      allowDisposableRgLifecycle: true,
    },
  });
  if (check.response.status < 200 || check.response.status >= 300) {
    throw new Error(
      `Failed live ownership check for disposable Resource Group "${options.rgName}" before mutating call: HTTP ${check.response.status}.`,
    );
  }
  const bodyObj =
    check.response.body && typeof check.response.body === "object"
      ? (check.response.body as Record<string, unknown>)
      : undefined;
  const tagsObj =
    bodyObj?.tags && typeof bodyObj.tags === "object"
      ? (bodyObj.tags as Record<string, unknown>)
      : undefined;
  const liveRunId =
    typeof tagsObj?.[RUN_OWNERSHIP_TAG] === "string" ? tagsObj[RUN_OWNERSHIP_TAG] : undefined;
  if (liveRunId !== options.expectedRunId) {
    throw new Error(
      `Blocked mutation in Resource Group "${options.rgName}": live ${RUN_OWNERSHIP_TAG} tag is "${liveRunId ?? "<missing>"}", expected "${options.expectedRunId}".`,
    );
  }
  return liveRunId;
}
