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
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export function sanitizeStringValue(
  raw: string,
  ctx: SanitizeContext,
  propertyName?: string,
  dotPath?: string,
  parentObject?: Record<string, unknown>,
): string {
  // Check explicit secret property paths (falling back to standalone parameter name for path/query/header scalars: #10 / #11)
  // as well as wildcard dictionary paths (e.g., "credentials.*.value") and secret key-name heuristics.
  const secretPaths = new Set((ctx.extraSecretPropertyPaths ?? []).map((p) => p.toLowerCase()));
  const candidatePath = (dotPath || propertyName || "").toLowerCase();
  const matchesExplicitSecret =
    Boolean(candidatePath) &&
    (secretPaths.has(candidatePath) ||
      (dotPath ? secretPaths.has(dotPath.toLowerCase()) : false) ||
      (propertyName && !dotPath ? secretPaths.has(propertyName.toLowerCase()) : false) ||
      [...secretPaths].some((sp) => {
        if (!sp.includes("*")) {
          return false;
        }
        const wildcardRe = new RegExp(`^${sp.split("*").map(escapeRegExp).join("[^.]+")}$`, "i");
        return wildcardRe.test(candidatePath);
      }));

  if (
    matchesExplicitSecret ||
    (propertyName &&
      (SECRET_KEY_NAME_RE.test(propertyName) || SECRET_SUBSTRING_KEY_RE.test(propertyName)))
  ) {
    if (/connectionstring/i.test(propertyName ?? "")) {
      return "Endpoint=https://contoso.azconfig.io;Id=0000;Secret=<redacted>";
    }
    return "<redacted>";
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
): unknown {
  if (typeof value === "string") {
    return sanitizeStringValue(value, ctx, propertyName, dotPath, parentObject);
  }
  if (Array.isArray(value)) {
    return value.map((item) => sanitizePayload(item, ctx, propertyName, `${dotPath}[]`));
  }
  if (value && typeof value === "object") {
    const rec = value as Record<string, unknown>;
    const sanitizedObj: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(rec)) {
      const nextPath = dotPath ? `${dotPath}.${k}` : k;
      const sanitizedKey = sanitizeStringValue(k, ctx);
      sanitizedObj[sanitizedKey] = sanitizePayload(v, ctx, k, nextPath, rec);
    }
    return sanitizedObj;
  }
  return value;
}
