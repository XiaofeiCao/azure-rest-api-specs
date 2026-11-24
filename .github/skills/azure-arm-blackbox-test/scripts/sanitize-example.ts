import type { SecretCycleRule, SecretStringConstraint } from "./types.ts";

const PLACEHOLDER_SUBSCRIPTION_ID = "00000000-0000-0000-0000-000000000000";
const PLACEHOLDER_TENANT_ID = "11111111-1111-1111-1111-111111111111";
const PLACEHOLDER_PRINCIPAL_ID = "22222222-2222-2222-2222-222222222222";
const PLACEHOLDER_CLIENT_ID = "33333333-3333-3333-3333-333333333333";
const PLACEHOLDER_RESOURCE_GROUP = "contosoResourceGroup";

const SECRET_KEY_NAME_RE =
  /^(password|secret|adminpassword|clientsecret|connectionstring|primarykey|secondarykey|primaryreadonlykey|secondaryreadonlykey|accesskey|apikey|sharedkey|sastoken|privatekey|keyvalue|token)$/i;

const SECRET_SUBSTRING_KEY_RE =
  /(password|secret|connectionstring|accesskey|apikey|sastoken|privatekey|sharedkey)/i;

const CONNECTION_STRING_VALUE_RE = /(AccountKey|SharedAccessKey|Secret|Password)\s*=\s*[^;]+/gi;

const SAS_SIG_VALUE_RE = /([?&](?:sig|s|c|h)=)[^&\s"]+/gi;
const JWT_VALUE_RE = /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g;

export interface SanitizeContext {
  subscriptionId?: string;
  disposableRgName?: string;
  armBaseUrl?: string;
  allowedArmOrigins?: string[];
  extraSecretPropertyPaths?: string[];
  secretQueryParamNames?: string[];
  secretPathTemplate?: string;
  secretPathSlotNames?: string[];
  secretCycleRules?: SecretCycleRule[];
  secretConstraints?: Record<string, SecretStringConstraint>;
  maxSecretCycleVariants?: number;
}

const DEFAULT_MAX_SECRET_CYCLE_VARIANTS = 2048;

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function escapeSecretPropertySegment(segment: string): string {
  return segment.replace(/\\/g, "\\\\").replace(/\./g, "\\.");
}

export function splitEscapedDotPath(dotPath: string): string[] {
  const parts: string[] = [];
  let cur = "";
  for (let i = 0; i < dotPath.length; i++) {
    const ch = dotPath[i];
    if (ch === "\\" && i + 1 < dotPath.length) {
      cur += dotPath[i + 1];
      i++;
    } else if (ch === ".") {
      parts.push(cur);
      cur = "";
    } else {
      cur += ch;
    }
  }
  parts.push(cur);
  return parts;
}

function parseSecretPatternSegments(pattern: string): string[] {
  const segments: string[] = [];
  for (const part of splitEscapedDotPath(pattern)) {
    let base = part;
    let arrayDepth = 0;
    // Expand EVERY trailing [] marker into a separate segment so nested arrays (e.g. credentials[][].opaqueMaterial) match (#4080)!
    while (base.endsWith("[]")) {
      arrayDepth++;
      base = base.slice(0, -2);
    }
    if (base.length > 0) {
      segments.push(base);
    }
    for (let i = 0; i < arrayDepth; i++) {
      segments.push("[]");
    }
  }
  return segments;
}

function matchesSecretSegments(patternSegs: string[], actualSegs: string[]): boolean {
  if (patternSegs.length !== actualSegs.length) {
    return false;
  }
  for (let i = 0; i < patternSegs.length; i++) {
    const pat = patternSegs[i];
    if (pat === "*") {
      // Matches ANY single dictionary key (including empty string "" or keys containing dots!)
      continue;
    }
    if (pat.toLowerCase() !== actualSegs[i].toLowerCase()) {
      return false;
    }
  }
  return true;
}

function foldCycleVariants(
  actualSegs: string[],
  cycleRules: SecretCycleRule[] | undefined,
  maxVariants = DEFAULT_MAX_SECRET_CYCLE_VARIANTS,
): string[][] {
  if (!cycleRules || cycleRules.length === 0 || actualSegs.length === 0) {
    return [actualSegs];
  }
  const parsedRules = cycleRules
    .map((r) => ({
      baseSegs: r.basePath ? parseSecretPatternSegments(r.basePath) : [],
      repeatSegs: parseSecretPatternSegments(r.repeatPath),
    }))
    .filter((r) => r.repeatSegs.length > 0);

  if (parsedRules.length === 0) {
    return [actualSegs];
  }

  const effectiveBudget = Math.max(1, maxVariants);
  const variants: string[][] = [actualSegs];
  const seen = new Set<string>([JSON.stringify(actualSegs)]);
  const queue: string[][] = [actualSegs];

  while (queue.length > 0) {
    const cur = queue.shift()!;
    for (const rule of parsedRules) {
      const bLen = rule.baseSegs.length;
      const rLen = rule.repeatSegs.length;
      if (cur.length < bLen + rLen) {
        continue;
      }
      if (
        matchesSecretSegments(rule.baseSegs, cur.slice(0, bLen)) &&
        matchesSecretSegments(rule.repeatSegs, cur.slice(bLen, bLen + rLen))
      ) {
        const reduced = [...cur.slice(0, bLen), ...cur.slice(bLen + rLen)];
        const key = JSON.stringify(reduced);
        if (!seen.has(key)) {
          if (variants.length >= effectiveBudget) {
            throw new Error(
              `Secret cycle reduction exceeded expansion budget (${effectiveBudget}) for path "${actualSegs.join(".")}"; aborting sanitization fail-closed to prevent credential leakage.`,
            );
          }
          seen.add(key);
          variants.push(reduced);
          queue.push(reduced);
        }
      }
    }
  }
  return variants;
}

function matchesAnyDeclaredSecretPath(actualSegs: string[], ctx: SanitizeContext): boolean {
  const rawSecretPaths = ctx.extraSecretPropertyPaths ?? [];
  if (rawSecretPaths.length === 0 || actualSegs.length === 0) {
    return false;
  }
  const variants = foldCycleVariants(actualSegs, ctx.secretCycleRules, ctx.maxSecretCycleVariants);
  for (const sp of rawSecretPaths) {
    const patSegs = parseSecretPatternSegments(sp);
    if (variants.some((v) => matchesSecretSegments(patSegs, v))) {
      return true;
    }
  }
  return false;
}

export function isPathOrAncestorDeclaredSecret(
  propPath: string,
  secretProperties: string[],
  secretCycleRules?: SecretCycleRule[],
): boolean {
  if (secretProperties.length === 0) {
    return false;
  }
  const segs = parseSecretPatternSegments(propPath);
  if (segs.length === 0) {
    return false;
  }
  const ctx: SanitizeContext = {
    extraSecretPropertyPaths: secretProperties,
    secretCycleRules,
  };
  for (let len = 1; len <= segs.length; len++) {
    if (matchesAnyDeclaredSecretPath(segs.slice(0, len), ctx)) {
      return true;
    }
  }
  return false;
}

function satisfiesConstraint(candidate: string, constraint: SecretStringConstraint): boolean {
  if (constraint.minLength !== undefined && candidate.length < constraint.minLength) {
    return false;
  }
  if (constraint.maxLength !== undefined && candidate.length > constraint.maxLength) {
    return false;
  }
  if (constraint.pattern !== undefined) {
    try {
      if (!new RegExp(constraint.pattern).test(candidate)) {
        return false;
      }
    } catch {
      // Ignore non-JS regex dialects.
    }
  }
  return true;
}

function adjustPlaceholderBounds(
  seed: string,
  padChar: string,
  constraint: SecretStringConstraint,
): string {
  let out = seed;
  if (
    constraint.maxLength !== undefined &&
    constraint.maxLength >= 0 &&
    out.length > constraint.maxLength
  ) {
    out = out.slice(0, constraint.maxLength);
  }
  if (constraint.minLength !== undefined && out.length < constraint.minLength) {
    out = out.padEnd(constraint.minLength, padChar);
  }
  return out;
}

function selectRedactedPlaceholder(
  propertyName: string | undefined,
  constraint: SecretStringConstraint | undefined,
): string {
  const defaultPlaceholder = /connectionstring/i.test(propertyName ?? "")
    ? "Endpoint=https://contoso.azconfig.io;Id=0000;Secret=<redacted>"
    : "<redacted>";

  if (!constraint || satisfiesConstraint(defaultPlaceholder, constraint)) {
    return defaultPlaceholder;
  }

  // Try constraint-safe non-secret placeholders when `<redacted>` violates @pattern/@minLength/@maxLength (#8063)!
  const seeds: Array<[string, string]> = [
    ["RedactedPlaceholder01", "a"],
    ["redactedplaceholder01", "a"],
    ["REDACTEDPLACEHOLDER01", "A"],
    ["RedactedSecretValue", "a"],
    ["000000000000", "0"],
    ["https://contoso.example.com/redacted", "a"],
    ["00000000-0000-0000-0000-000000000000", "0"],
    ["", "a"],
  ];

  for (const [seed, padChar] of seeds) {
    const candidate = adjustPlaceholderBounds(seed, padChar, constraint);
    if (satisfiesConstraint(candidate, constraint)) {
      return candidate;
    }
  }

  return adjustPlaceholderBounds("Redacted01", "a", constraint);
}

function findMatchingSecretConstraint(
  ctx: SanitizeContext,
  propertyName: string | undefined,
  dotPath: string | undefined,
  effectiveSegments: string[],
): SecretStringConstraint | undefined {
  const map = ctx.secretConstraints;
  if (!map) {
    return undefined;
  }
  if (dotPath && map[dotPath.toLowerCase()]) {
    return map[dotPath.toLowerCase()];
  }
  const variants = foldCycleVariants(
    effectiveSegments,
    ctx.secretCycleRules,
    ctx.maxSecretCycleVariants,
  );
  for (const [patKey, constraint] of Object.entries(map)) {
    const patSegs = parseSecretPatternSegments(patKey);
    if (variants.some((v) => matchesSecretSegments(patSegs, v))) {
      return constraint;
    }
  }
  if (propertyName && !dotPath && map[propertyName.toLowerCase()]) {
    return map[propertyName.toLowerCase()];
  }
  return undefined;
}

export function sanitizeUrlSecretParameters(
  rawUrl: string,
  options: {
    armBaseUrl?: string;
    secretQueryParamNames?: string[];
    secretPathTemplate?: string;
    secretPathSlotNames?: string[];
  },
): string {
  const isAbsolute = /^https?:\/\//i.test(rawUrl);
  const looksLikeRelativeUrl = !isAbsolute && (rawUrl.startsWith("/") || rawUrl.includes("?"));
  if (!isAbsolute && !looksLikeRelativeUrl) {
    return rawUrl;
  }

  let parsed: URL;
  try {
    parsed = isAbsolute ? new URL(rawUrl) : new URL(rawUrl, "https://management.azure.com");
  } catch {
    return rawUrl;
  }

  const secretQueryLower = new Set(
    (options.secretQueryParamNames ?? []).map((n) => n.toLowerCase()),
  );
  let mutated = false;

  for (const key of [...parsed.searchParams.keys()]) {
    const lowerKey = key.toLowerCase();
    if (
      secretQueryLower.has(lowerKey) ||
      SECRET_KEY_NAME_RE.test(key) ||
      SECRET_SUBSTRING_KEY_RE.test(key)
    ) {
      parsed.searchParams.set(key, "<redacted>");
      mutated = true;
    }
  }

  const secretSlotsLower = new Set((options.secretPathSlotNames ?? []).map((s) => s.toLowerCase()));
  if (secretSlotsLower.size > 0 && options.secretPathTemplate) {
    let basePrefix = "";
    if (options.armBaseUrl) {
      try {
        const baseObj = new URL(options.armBaseUrl);
        if (!isAbsolute || parsed.origin.toLowerCase() === baseObj.origin.toLowerCase()) {
          basePrefix = baseObj.pathname.replace(/\/+$/, "");
        }
      } catch {
        // Ignore invalid base URL.
      }
    }
    const rawPath = parsed.pathname;
    const strippedPath =
      basePrefix && rawPath.toLowerCase().startsWith(`${basePrefix.toLowerCase()}/`)
        ? rawPath.slice(basePrefix.length)
        : rawPath;
    const tSegs = options.secretPathTemplate
      .split("?")[0]
      .replace(/^\/+|\/+$/g, "")
      .split("/");
    const aSegs = strippedPath.replace(/^\/+|\/+$/g, "").split("/");
    if (tSegs.length === aSegs.length) {
      let slotReplaced = false;
      for (let i = 0; i < tSegs.length; i++) {
        const m = /^\{([^}]+)\}$/.exec(tSegs[i]);
        if (m && secretSlotsLower.has(m[1].toLowerCase())) {
          aSegs[i] = "<redacted>";
          slotReplaced = true;
        }
      }
      if (slotReplaced) {
        parsed.pathname = `${basePrefix}/${aSegs.join("/")}`;
        mutated = true;
      }
    }
  }

  if (!mutated) {
    return rawUrl;
  }
  const rebuilt = isAbsolute
    ? parsed.toString()
    : `${parsed.pathname}${parsed.search}${parsed.hash}`;
  return rebuilt.replace(/%3Credacted%3E/gi, "<redacted>");
}

export function sanitizeStringValue(
  raw: string,
  ctx: SanitizeContext,
  propertyName?: string,
  dotPath?: string,
  parentObject?: Record<string, unknown>,
  pathSegments?: string[],
  forceSecretSubtree = false,
): string {
  const rawSecretPaths = ctx.extraSecretPropertyPaths ?? [];
  const secretPathsLower = new Set(rawSecretPaths.map((p) => p.toLowerCase()));
  const effectiveSegments =
    pathSegments && pathSegments.length > 0
      ? pathSegments
      : dotPath
        ? parseSecretPatternSegments(dotPath)
        : propertyName !== undefined
          ? [propertyName]
          : [];
  const candidatePath = (dotPath || propertyName || "").toLowerCase();

  const matchesExplicitSecret =
    forceSecretSubtree ||
    (!pathSegments?.length && Boolean(candidatePath) && secretPathsLower.has(candidatePath)) ||
    (propertyName && !dotPath && (!pathSegments || pathSegments.length === 0)
      ? secretPathsLower.has(propertyName.toLowerCase())
      : false) ||
    matchesAnyDeclaredSecretPath(effectiveSegments, ctx);

  if (
    matchesExplicitSecret ||
    (propertyName &&
      (SECRET_KEY_NAME_RE.test(propertyName) || SECRET_SUBSTRING_KEY_RE.test(propertyName)))
  ) {
    const constraint = findMatchingSecretConstraint(ctx, propertyName, dotPath, effectiveSegments);
    return selectRedactedPlaceholder(propertyName, constraint);
  }

  // Handle ApiKey objects where secret value is stored in a sibling "value" field next to "connectionString" + "readOnly".
  if (
    propertyName?.toLowerCase() === "value" &&
    parentObject &&
    ("connectionString" in parentObject || "keyName" in parentObject) &&
    !("contentType" in parentObject)
  ) {
    return "<redacted>";
  }

  let text = raw;

  // Redact @secret query and path parameters on URLs before normalizing hostnames/GUIDs (#60682).
  text = sanitizeUrlSecretParameters(text, {
    armBaseUrl: ctx.armBaseUrl,
    secretQueryParamNames: ctx.secretQueryParamNames,
    secretPathTemplate: ctx.secretPathTemplate,
    secretPathSlotNames: ctx.secretPathSlotNames,
  });

  // Normalize custom Canary / EUAP / Dogfood / loopback ARM base URLs to canonical https://management.azure.com.
  if (ctx.armBaseUrl) {
    const cleanBase = ctx.armBaseUrl.replace(/\/+$/, "");
    if (cleanBase && cleanBase.toLowerCase() !== "https://management.azure.com") {
      text = text.replace(
        new RegExp(escapeRegExp(cleanBase), "gi"),
        "https://management.azure.com",
      );
      try {
        const baseOrigin = new URL(cleanBase).origin;
        if (baseOrigin.toLowerCase() !== "https://management.azure.com") {
          text = text.replace(
            new RegExp(escapeRegExp(baseOrigin), "gi"),
            "https://management.azure.com",
          );
        }
      } catch {
        // Ignore non-URL strings.
      }
    }
  }
  for (const allowedOrigin of ctx.allowedArmOrigins ?? []) {
    const cleanOrigin = allowedOrigin.replace(/\/+$/, "");
    if (cleanOrigin && cleanOrigin.toLowerCase() !== "https://management.azure.com") {
      text = text.replace(
        new RegExp(escapeRegExp(cleanOrigin), "gi"),
        "https://management.azure.com",
      );
    }
  }
  text = text.replace(
    /https:\/\/(?:[a-z0-9-]+\.)?(?:management\.azure\.com|api-dogfood\.resources\.windows-int\.net)\b/gi,
    "https://management.azure.com",
  );

  if (ctx.subscriptionId) {
    const subRe = new RegExp(escapeRegExp(ctx.subscriptionId), "gi");
    text = text.replace(subRe, PLACEHOLDER_SUBSCRIPTION_ID);
  }
  if (ctx.disposableRgName) {
    const rgRe = new RegExp(escapeRegExp(ctx.disposableRgName), "gi");
    text = text.replace(rgRe, PLACEHOLDER_RESOURCE_GROUP);
  }

  // Replace any residual rg-arm-blackbox-* names.
  text = text.replace(/\brg-arm-blackbox-[a-z0-9-]+\b/gi, PLACEHOLDER_RESOURCE_GROUP);

  // Scrub embedded connection string secrets, SAS signatures, and JWT tokens.
  text = text.replace(CONNECTION_STRING_VALUE_RE, "$1=<redacted>");
  text = text.replace(SAS_SIG_VALUE_RE, "$1<redacted>");
  text = text.replace(JWT_VALUE_RE, "<redacted-jwt>");

  // Normalize systemData / identity PII emails (e.g. createdBy / lastModifiedBy).
  const lowerProp = propertyName?.toLowerCase() ?? "";
  if (
    (lowerProp === "createdby" || lowerProp === "lastmodifiedby" || lowerProp.includes("email")) &&
    text.includes("@")
  ) {
    return "user@contoso.com";
  }

  // Normalize identity GUIDs by property name.
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text)) {
    if (lowerProp.includes("tenantid")) {
      return PLACEHOLDER_TENANT_ID;
    }
    if (lowerProp.includes("principalid")) {
      return PLACEHOLDER_PRINCIPAL_ID;
    }
    if (lowerProp.includes("clientid")) {
      return PLACEHOLDER_CLIENT_ID;
    }
    if (lowerProp.includes("subscriptionid")) {
      return PLACEHOLDER_SUBSCRIPTION_ID;
    }
  }

  // Also sanitize subscription GUIDs inside ARM resource ID strings.
  text = text.replace(
    /(\/subscriptions\/)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi,
    `$1${PLACEHOLDER_SUBSCRIPTION_ID}`,
  );

  return text;
}

export function sanitizePayload(
  value: unknown,
  ctx: SanitizeContext,
  propertyName?: string,
  dotPath = "",
  parentObject?: Record<string, unknown>,
  pathSegments: string[] = [],
  forceSecretSubtree = false,
): unknown {
  // Propagate @secret status from any matched container object/array (including root whole-body @secret parameters)
  // through all its descendants (#7801, #60746)!
  const rootPropertySegments =
    pathSegments.length > 0 ? pathSegments : propertyName ? [propertyName] : [];
  const isSecretContainer =
    forceSecretSubtree ||
    (rootPropertySegments.length > 0 && matchesAnyDeclaredSecretPath(rootPropertySegments, ctx)) ||
    Boolean(
      propertyName &&
      (SECRET_KEY_NAME_RE.test(propertyName) || SECRET_SUBSTRING_KEY_RE.test(propertyName)),
    );

  if (typeof value === "string") {
    return sanitizeStringValue(
      value,
      ctx,
      propertyName,
      dotPath,
      parentObject,
      pathSegments,
      isSecretContainer,
    );
  }
  if (Array.isArray(value)) {
    return value.map((item) =>
      sanitizePayload(
        item,
        ctx,
        propertyName,
        `${dotPath}[]`,
        undefined,
        [...pathSegments, "[]"],
        isSecretContainer,
      ),
    );
  }
  if (value && typeof value === "object") {
    const rec = value as Record<string, unknown>;
    const sanitizedObj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(rec)) {
      const nextPath = dotPath ? `${dotPath}.${k}` : k;
      const sanitizedKey = sanitizeStringValue(k, ctx);
      sanitizedObj[sanitizedKey] = sanitizePayload(
        v,
        ctx,
        k,
        nextPath,
        rec,
        [...pathSegments, k],
        isSecretContainer,
      );
    }
    return sanitizedObj;
  }
  return value;
}
