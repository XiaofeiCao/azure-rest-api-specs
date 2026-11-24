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
  extraSecretPropertyPaths?: string[];
  secretCycleRules?: SecretCycleRule[];
  secretConstraints?: Record<string, SecretStringConstraint>;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function parseSecretPatternSegments(pattern: string): string[] {
  const segments: string[] = [];
  for (const part of pattern.split(".")) {
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

  const variants: string[][] = [actualSegs];
  const seen = new Set<string>([JSON.stringify(actualSegs)]);
  const queue: string[][] = [actualSegs];

  while (queue.length > 0 && variants.length < 32) {
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
  const variants = foldCycleVariants(actualSegs, ctx.secretCycleRules);
  for (const sp of rawSecretPaths) {
    const patSegs = parseSecretPatternSegments(sp);
    if (variants.some((v) => matchesSecretSegments(patSegs, v))) {
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
  const variants = foldCycleVariants(effectiveSegments, ctx.secretCycleRules);
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
  // Propagate @secret status from any matched container object/array through all its descendants (#7801)!
  const isSecretContainer =
    forceSecretSubtree ||
    (pathSegments.length > 0 && matchesAnyDeclaredSecretPath(pathSegments, ctx)) ||
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
