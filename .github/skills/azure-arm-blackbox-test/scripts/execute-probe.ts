import * as crypto from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import {
  analyzeBehavioralDiscrepancies,
  extractProvisioningState,
  isFailedOrCanceledState,
  isNonTerminalProvisioningState,
  runTypeSpecLiveValidation,
  runTypeSpecMonitorResultValidation,
} from "./analyze-behavior.ts";
import {
  getArmBearerToken,
  parseRetryAfterMs,
  resolveArmRelativeOrAbsoluteUrl,
  safeDecodeUriSegment,
  sendRawHttpExchange,
  stripConfiguredArmBasePath,
  verifyLiveDisposableRgOwnership,
  type SafetyGuardContext,
} from "./auth-and-http.ts";
import { loadLedger, nextTraceSequence, saveLedger, saveProbeTrace } from "./ledger-store.ts";
import { sanitizeUrlSecretParameters } from "./sanitize-example.ts";
import type {
  CoverageLedger,
  LedgerRuntimeState,
  ObservedLroBehavior,
  OperationContract,
  OperationParameterSpec,
  OwnedTargetResource,
  ProbeRequestInput,
  ProbeTrace,
  WireHttpExchange,
} from "./types.ts";

export interface ExecuteProbeOptions {
  workDir: string;
  input: ProbeRequestInput;
  bearerToken?: string;
}

function ensureRuntimeState(ledger: CoverageLedger): LedgerRuntimeState {
  if (!ledger.runtimeState) {
    ledger.runtimeState = {
      pathSlotValues: {},
      putBodiesByResourceType: {},
      listItemNamesByResourceType: {},
    };
  }
  return ledger.runtimeState;
}

function applyBoundsPreservingSuffix(
  prefix: string,
  suffix: string,
  separator: string,
  minLen: number | undefined,
  maxLen: number | undefined,
  padChar = "a",
): string {
  const effectiveMax = maxLen !== undefined && maxLen > 0 ? maxLen : undefined;
  let candidate: string;
  if (effectiveMax !== undefined) {
    if (effectiveMax <= suffix.length) {
      candidate = suffix.slice(-effectiveMax);
    } else {
      const budgetForPrefix = effectiveMax - suffix.length - separator.length;
      if (budgetForPrefix <= 0) {
        candidate = `${prefix.slice(0, effectiveMax - suffix.length)}${suffix}`;
      } else {
        const trimmedPrefix = prefix.slice(0, budgetForPrefix);
        candidate = `${trimmedPrefix}${separator}${suffix}`;
      }
    }
  } else {
    candidate = `${prefix}${separator}${suffix}`;
  }

  if (minLen !== undefined && candidate.length < minLen) {
    const padCount = minLen - candidate.length;
    // Pad between prefix and suffix so the unique run suffix stays intact at the end (#8038)!
    const idx = candidate.length - suffix.length;
    candidate = `${candidate.slice(0, idx)}${padChar.repeat(padCount)}${suffix}`;
  }
  return candidate;
}

function synthesizeSlotName(
  slotName: string,
  paramSpec: OperationParameterSpec | undefined,
  serviceHint: string,
  runId: string,
): string {
  // Seed with persisted per-run identifier so separate/concurrent runs never collide on global names (#8038)!
  const hexSuffix = crypto
    .createHash("sha1")
    .update(`${runId}:${serviceHint}:${slotName}`)
    .digest("hex")
    .slice(0, 6);
  const alphaSuffix = [...hexSuffix]
    .map((ch) => (ch >= "0" && ch <= "9" ? String.fromCharCode(97 + Number(ch)) : ch))
    .join("");
  const cleanSlot = slotName
    .replace(/Name$/i, "")
    .replace(/[^a-zA-Z0-9]/g, "")
    .toLowerCase()
    .slice(0, 8);
  const basePrefix = `bbx${cleanSlot || "res"}`;

  const candidateTemplates = [
    applyBoundsPreservingSuffix(
      `bbx-${cleanSlot || "res"}`,
      hexSuffix,
      "-",
      paramSpec?.minLength,
      paramSpec?.maxLength,
      "a",
    ),
    applyBoundsPreservingSuffix(
      basePrefix,
      hexSuffix,
      "",
      paramSpec?.minLength,
      paramSpec?.maxLength,
      "a",
    ),
    applyBoundsPreservingSuffix(
      basePrefix,
      alphaSuffix,
      "",
      paramSpec?.minLength,
      paramSpec?.maxLength,
      "a",
    ),
    applyBoundsPreservingSuffix(
      `bbx_${cleanSlot || "res"}`,
      hexSuffix,
      "_",
      paramSpec?.minLength,
      paramSpec?.maxLength,
      "a",
    ),
    applyBoundsPreservingSuffix(
      `Bbx${(cleanSlot || "res").charAt(0).toUpperCase()}${(cleanSlot || "res").slice(1)}`,
      hexSuffix,
      "",
      paramSpec?.minLength,
      paramSpec?.maxLength,
      "a",
    ),
  ];

  if (!paramSpec?.pattern) {
    return candidateTemplates[0];
  }

  let patternRegex: RegExp | undefined;
  try {
    patternRegex = new RegExp(paramSpec.pattern);
  } catch {
    return candidateTemplates[0];
  }

  // Validate actual candidates against the parameter's @pattern (#8069)!
  for (const cand of candidateTemplates) {
    if (patternRegex.test(cand)) {
      return cand;
    }
  }

  throw new Error(
    `Cannot deterministically synthesize path parameter "{${slotName}}" matching @pattern(${JSON.stringify(paramSpec.pattern)}); supply pathParams.${slotName} explicitly.`,
  );
}

function doesUrlMatchPathTemplate(
  pathTemplate: string,
  actualUrl: string,
  parameters: OperationParameterSpec[] = [],
  armBaseUrl?: string,
): boolean {
  const cleanTemplate = pathTemplate.split("?")[0].replace(/^\/+|\/+$/g, "");
  const actualPathname = stripConfiguredArmBasePath(actualUrl, armBaseUrl).replace(
    /^\/+|\/+$/g,
    "",
  );
  const templateSegs = cleanTemplate.split("/").filter(Boolean);
  const regexStr = templateSegs
    .map((seg) => {
      const m = /^\{([^}]+)\}$/.exec(seg);
      if (m) {
        const slotName = m[1];
        const paramSpec = parameters.find(
          (p) => p.in === "path" && p.name.toLowerCase() === slotName.toLowerCase(),
        );
        // Allow slash-spanning matches for any @path(#{ allowReserved: true }) parameter as well as {scope} (#4158)!
        const canSpanSlashes =
          Boolean(paramSpec?.allowReserved) || slotName.toLowerCase() === "scope";
        return canSpanSlashes ? "(.+)" : "([^/]+)";
      }
      return seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("\\/");
  return new RegExp(`^${regexStr}$`, "i").test(actualPathname);
}

function extractPathSlotsFromUrl(
  pathTemplate: string,
  actualUrl: string,
  armBaseUrl?: string,
): Record<string, string> {
  const cleanTemplate = pathTemplate.split("?")[0].replace(/^\/+|\/+$/g, "");
  const actualPathname = stripConfiguredArmBasePath(actualUrl, armBaseUrl).replace(
    /^\/+|\/+$/g,
    "",
  );
  const templateSegs = cleanTemplate.split("/");
  const actualSegs = actualPathname.split("/");
  const extracted: Record<string, string> = {};

  if (templateSegs.length === actualSegs.length) {
    for (let i = 0; i < templateSegs.length; i++) {
      const m = /^\{([^}]+)\}$/.exec(templateSegs[i]);
      if (m) {
        extracted[m[1]] = safeDecodeUriSegment(actualSegs[i]);
      }
    }
    return extracted;
  }

  const paramNames: string[] = [];
  const regexStr = templateSegs
    .map((seg) => {
      const m = /^\{([^}]+)\}$/.exec(seg);
      if (m) {
        paramNames.push(m[1]);
        return "(.+?)";
      }
      return seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("\\/");
  const match = new RegExp(`^${regexStr}$`, "i").exec(actualPathname);
  if (match) {
    paramNames.forEach((name, idx) => {
      extracted[name] = safeDecodeUriSegment(match[idx + 1]);
    });
  }
  return extracted;
}

function interpolatePathTemplate(
  ledger: CoverageLedger,
  contract: OperationContract,
  input: ProbeRequestInput,
): string {
  if (input.pathOrUrl && input.pathOrUrl.trim().length > 0) {
    return input.pathOrUrl;
  }

  const state = ensureRuntimeState(ledger);
  const overrides = input.pathParams ?? {};
  const cleanTemplate = contract.pathTemplate.split("?")[0];
  const segments = cleanTemplate.split("/");

  // Identify the leaf path parameter name so List-discovered child names bind only to the leaf slot.
  const allSlots = [...cleanTemplate.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
  const leafSlot = allSlots[allSlots.length - 1];

  const resolvedSegments = segments.map((seg) => {
    const slotMatch = /^\{([^}]+)\}$/.exec(seg);
    if (!slotMatch) {
      return seg;
    }
    const slotName = slotMatch[1];
    const lowerSlot = slotName.toLowerCase();
    const paramSpec = contract.parameters.find(
      (p) => p.in === "path" && p.name.toLowerCase() === lowerSlot,
    );

    const explicitVal =
      overrides[slotName] ??
      Object.entries(overrides).find(([k]) => k.toLowerCase() === lowerSlot)?.[1];

    let rawValue: string | undefined = explicitVal;

    if (rawValue === undefined) {
      if (lowerSlot === "subscriptionid") {
        if (!ledger.subscriptionId) {
          throw new Error(
            `Cannot interpolate {${slotName}} for ${contract.operationId}: subscriptionId is not set in coverage-ledger.json.`,
          );
        }
        rawValue = ledger.subscriptionId;
      } else if (lowerSlot === "resourcegroupname" || lowerSlot === "resourcegroup") {
        if (!ledger.disposableResourceGroup?.name) {
          throw new Error(
            `Cannot interpolate {${slotName}} for ${contract.operationId}: disposable Resource Group is not created yet.`,
          );
        }
        rawValue = ledger.disposableResourceGroup.name;
      } else if (lowerSlot === "location" || lowerSlot === "locationname") {
        rawValue = ledger.location ?? ledger.disposableResourceGroup?.location ?? "eastus";
      }
    }

    if (
      rawValue === undefined &&
      !(input.expectError && slotName === leafSlot && (input.method ?? contract.method) === "GET")
    ) {
      rawValue =
        state.pathSlotValues[slotName] ??
        Object.entries(state.pathSlotValues).find(([k]) => k.toLowerCase() === lowerSlot)?.[1];
    }

    if (rawValue === undefined && slotName === leafSlot && !input.expectError) {
      const listDiscovered = state.listItemNamesByResourceType[contract.resourceType]?.[0];
      if (listDiscovered) {
        rawValue = listDiscovered;
      }
    }

    if (rawValue === undefined && paramSpec?.enumValues?.length === 1) {
      rawValue = paramSpec.enumValues[0];
    }

    if (rawValue === undefined) {
      if (lowerSlot === "scope") {
        throw new Error(
          `Operation ${contract.operationId} requires pathParams.scope (untyped ARM extension scope).`,
        );
      }
      rawValue = input.expectError
        ? `missing-${slotName.toLowerCase().slice(0, 12)}`
        : synthesizeSlotName(
            slotName,
            paramSpec,
            ledger.serviceName,
            ledger.runId ?? ledger.disposableResourceGroup?.name ?? "default-run",
          );
    }

    const preserveSlashes = Boolean(paramSpec?.allowReserved) || lowerSlot === "scope";
    if (preserveSlashes) {
      return rawValue
        .replace(/^\/+/, "")
        .split("/")
        .map((part) => encodeURIComponent(part))
        .join("/");
    }
    return encodeURIComponent(rawValue);
  });

  return resolvedSegments.join("/");
}

export function buildTargetUrl(
  armBaseUrl: string,
  pathOrUrl: string,
  apiVersion: string,
  extraQuery?: Record<string, string>,
): string {
  const rawUrl = resolveArmRelativeOrAbsoluteUrl(armBaseUrl, pathOrUrl);
  const parsed = new URL(rawUrl);

  for (const [existingKey, existingVal] of [...parsed.searchParams.entries()]) {
    if (existingKey.toLowerCase() === "api-version") {
      if (apiVersion && existingVal !== apiVersion) {
        throw new Error(
          `Conflicting api-version "${existingVal}" in probe URL: contract requires "${apiVersion}".`,
        );
      }
      parsed.searchParams.delete(existingKey);
    }
  }

  for (const [k, v] of Object.entries(extraQuery ?? {})) {
    if (k.toLowerCase() === "api-version") {
      if (apiVersion && v !== apiVersion) {
        throw new Error(
          `Conflicting api-version "${v}" in query parameters: contract requires "${apiVersion}".`,
        );
      }
      continue;
    }
    parsed.searchParams.set(k, v);
  }

  if (apiVersion) {
    parsed.searchParams.set("api-version", apiVersion);
  }
  return parsed.toString();
}

function resolvePollingUrl(armBaseUrl: string, headerVal: string): string {
  return resolveArmRelativeOrAbsoluteUrl(armBaseUrl, headerVal);
}

function extractAsyncMonitorStatus(body: unknown): string | undefined {
  if (!body || typeof body !== "object") {
    return undefined;
  }
  const rec = body as Record<string, unknown>;
  if (typeof rec.status === "string" && rec.status.trim()) {
    return rec.status.trim();
  }
  return extractProvisioningState(body);
}

function extractTargetResourceIdentityFromUrl(
  urlStr: string,
  fallbackLocation?: string,
  responseBody?: unknown,
  armBaseUrl?: string,
): OwnedTargetResource | undefined {
  try {
    const encodedPathname = stripConfiguredArmBasePath(urlStr, armBaseUrl).replace(/\/+$/, "");
    const rgMatch =
      /^\/subscriptions\/[^/]+\/resourcegroups\/([^/]+)\/providers\/([^/]+)\/([^/]+)\/([^/]+)$/i.exec(
        encodedPathname,
      );
    if (!rgMatch) {
      return undefined;
    }
    const rgName = safeDecodeUriSegment(rgMatch[1]);
    const providerNamespace = safeDecodeUriSegment(rgMatch[2]);
    const collectionSegment = safeDecodeUriSegment(rgMatch[3]);
    const resourceName = safeDecodeUriSegment(rgMatch[4]);
    const decodedId = encodedPathname
      .split("/")
      .map((s) => safeDecodeUriSegment(s))
      .join("/");
    const bodyLocation =
      responseBody &&
      typeof responseBody === "object" &&
      typeof (responseBody as Record<string, unknown>).location === "string"
        ? String((responseBody as Record<string, unknown>).location)
        : fallbackLocation;
    return {
      providerNamespace,
      collectionSegment,
      name: resourceName,
      location: bodyLocation,
      resourceGroupName: rgName,
      resourceId: decodedId,
    };
  } catch {
    return undefined;
  }
}

function getOwnedTargetResourcesFromLedger(ledger: CoverageLedger): OwnedTargetResource[] {
  const owned: OwnedTargetResource[] = [];
  for (const f of ledger.provisionedFixtures) {
    if (f.kind !== "target-rp-resource") {
      continue;
    }
    const meta = f.metadata ?? {};
    if (typeof meta.providerNamespace === "string" && typeof meta.collectionSegment === "string") {
      owned.push({
        providerNamespace: meta.providerNamespace,
        collectionSegment: meta.collectionSegment,
        name: f.name,
        location: typeof meta.location === "string" ? meta.location : ledger.location,
        resourceGroupName:
          typeof meta.resourceGroupName === "string"
            ? meta.resourceGroupName
            : ledger.disposableResourceGroup?.name,
        resourceId: f.resourceId,
      });
    } else {
      const parsed = extractTargetResourceIdentityFromUrl(
        `https://management.azure.com${f.resourceId.startsWith("/") ? "" : "/"}${f.resourceId}`,
        ledger.location,
      );
      if (parsed) {
        owned.push(parsed);
      }
    }
  }
  return owned;
}

function detectInitialLroSignals(
  contract: OperationContract,
  initial: WireHttpExchange,
): {
  signals: string[];
  pollingHeaderUsed?: ObservedLroBehavior["pollingHeaderUsed"];
  pollTargetUrl?: string;
} {
  const signals: string[] = [];
  const status = initial.response.status;
  const headers = initial.response.headers;
  const provState = extractProvisioningState(initial.response.body);

  if (status === 202) {
    signals.push("http-202-accepted");
  }
  if (headers["azure-asyncoperation"]) {
    signals.push("header-azure-asyncoperation");
  }
  if (headers["operation-location"]) {
    signals.push("header-operation-location");
  }
  if (
    headers.location &&
    (status === 202 ||
      (status === 201 &&
        (contract.isLroDeclared || contract.method === "POST" || contract.method === "DELETE")))
  ) {
    signals.push("header-location");
  }
  if (isNonTerminalProvisioningState(provState)) {
    signals.push(`non-terminal-provisioning-state:${provState}`);
  }

  if (signals.length === 0) {
    return { signals };
  }

  if (headers["azure-asyncoperation"]) {
    return {
      signals,
      pollingHeaderUsed: "azure-asyncoperation",
      pollTargetUrl: headers["azure-asyncoperation"],
    };
  }
  if (headers["operation-location"]) {
    return {
      signals,
      pollingHeaderUsed: "operation-location",
      pollTargetUrl: headers["operation-location"],
    };
  }
  if (headers.location) {
    return {
      signals,
      pollingHeaderUsed: "location",
      pollTargetUrl: headers.location,
    };
  }
  if (
    isNonTerminalProvisioningState(provState) &&
    (contract.method === "PUT" || contract.method === "PATCH")
  ) {
    return {
      signals,
      pollingHeaderUsed: "resource-get",
      pollTargetUrl: initial.request.url,
    };
  }

  return { signals };
}

export async function executeOperationProbe(
  options: ExecuteProbeOptions,
): Promise<{ trace: ProbeTrace; traceFile: string }> {
  const ledger = loadLedger(options.workDir);
  const { input } = options;
  const contract = ledger.operations[input.operationId];
  if (!contract) {
    throw new Error(
      `Unknown operationId "${input.operationId}". Available operations: ${Object.keys(ledger.operations).join(", ")}`,
    );
  }

  const token = getArmBearerToken({
    explicitToken: options.bearerToken,
    subscriptionId: ledger.subscriptionId,
    armBaseUrl: ledger.armBaseUrl,
    tokenResource: ledger.armTokenResource,
  });

  if (!ledger.runId) {
    ledger.runId = crypto.randomBytes(4).toString("hex");
  }
  const runtimeState = ensureRuntimeState(ledger);
  const ownedTargetResources = getOwnedTargetResourcesFromLedger(ledger);
  const expectError = Boolean(input.expectError);
  const method = input.method ?? contract.method;
  if (!expectError && method.toUpperCase() !== contract.method.toUpperCase()) {
    throw new Error(
      `Positive probe for "${contract.operationId}" must use declared HTTP method "${contract.method}" (got "${method}"). Set expectError: true for deliberate off-contract negative probes.`,
    );
  }

  const resolvedPathOrUrl = interpolatePathTemplate(ledger, contract, input);
  const targetUrl = buildTargetUrl(
    ledger.armBaseUrl,
    resolvedPathOrUrl,
    contract.apiVersion,
    input.query,
  );
  if (
    !expectError &&
    !doesUrlMatchPathTemplate(
      contract.pathTemplate,
      targetUrl,
      contract.parameters,
      ledger.armBaseUrl,
    )
  ) {
    throw new Error(
      `Positive probe URL "${stripConfiguredArmBasePath(targetUrl, ledger.armBaseUrl)}" does not match declared route template "${contract.pathTemplate}" for "${contract.operationId}".`,
    );
  }

  const upperMethod = method.toUpperCase();
  const isReadOnlyMethod =
    upperMethod === "GET" || upperMethod === "HEAD" || upperMethod === "OPTIONS";
  const isCheckNameAvail =
    upperMethod === "POST" &&
    /\/checknameavailability$/i.test(stripConfiguredArmBasePath(targetUrl, ledger.armBaseUrl));

  let verifiedRgRunIdTag: string | undefined;
  const expectedRunId = ledger.disposableResourceGroup?.runId ?? ledger.runId;
  if (!isReadOnlyMethod && !isCheckNameAvail) {
    if (!ledger.subscriptionId || !ledger.disposableResourceGroup) {
      throw new Error(
        `Blocked mutating ${upperMethod} probe for "${contract.operationId}": disposable Resource Group is not created yet.`,
      );
    }
    if (ledger.disposableResourceGroup.cleanupStatus !== "active") {
      throw new Error(
        `Blocked mutating ${upperMethod} probe for "${contract.operationId}": disposable Resource Group "${ledger.disposableResourceGroup.name}" has cleanupStatus "${ledger.disposableResourceGroup.cleanupStatus}".`,
      );
    }
    if (!expectedRunId) {
      throw new Error(
        `Blocked mutating ${upperMethod} probe for "${contract.operationId}": missing runId ownership marker in ledger.`,
      );
    }
    verifiedRgRunIdTag = await verifyLiveDisposableRgOwnership({
      armBaseUrl: ledger.armBaseUrl,
      allowedArmOrigins: ledger.allowedArmOrigins,
      subscriptionId: ledger.subscriptionId,
      rgName: ledger.disposableResourceGroup.name,
      expectedRunId,
      bearerToken: token,
    });
  }

  const safetyContext: SafetyGuardContext = {
    trustedArmBaseUrl: ledger.armBaseUrl,
    allowedArmOrigins: ledger.allowedArmOrigins,
    subscriptionId: ledger.subscriptionId,
    disposableRgName: ledger.disposableResourceGroup?.name,
    disposableRgCleanupStatus: ledger.disposableResourceGroup?.cleanupStatus,
    expectedRunId,
    verifiedRgRunIdTag,
    ownedTargetResources,
    allowDisposableRgLifecycle: false,
  };

  const secretHeaderNames = [
    ...new Set([
      ...contract.parameters
        .filter((p) => p.in === "header" && p.secretCandidate)
        .map((p) => p.name),
      ...(contract.secretResponseHeaders ?? []),
    ]),
  ];

  const exchanges: WireHttpExchange[] = [];
  const initialExchange = await sendRawHttpExchange({
    step: "initial",
    method,
    url: targetUrl,
    bearerToken: token,
    headers: input.headers,
    extraSensitiveHeaders: secretHeaderNames,
    body: input.body,
    safetyContext,
  });
  exchanges.push(initialExchange);

  // Track created top-level target-RP resource identities inside our disposable RG so soft-delete purge
  // is permitted ONLY for matching (providerNamespace, collectionSegment, location, name) (#7821).
  if (
    method === "PUT" &&
    initialExchange.response.status >= 200 &&
    initialExchange.response.status < 300
  ) {
    const reqLocation =
      input.body &&
      typeof input.body === "object" &&
      typeof (input.body as Record<string, unknown>).location === "string"
        ? String((input.body as Record<string, unknown>).location)
        : ledger.location;
    const identity = extractTargetResourceIdentityFromUrl(
      targetUrl,
      reqLocation,
      initialExchange.response.body,
      ledger.armBaseUrl,
    );
    if (
      identity &&
      !ledger.provisionedFixtures.some(
        (f) => f.resourceId.toLowerCase() === identity.resourceId.toLowerCase(),
      )
    ) {
      ledger.provisionedFixtures.push({
        kind: "target-rp-resource",
        name: identity.name,
        resourceId: identity.resourceId,
        provisionedAt: new Date().toISOString(),
        metadata: {
          providerNamespace: identity.providerNamespace,
          collectionSegment: identity.collectionSegment,
          location: identity.location,
          resourceGroupName: identity.resourceGroupName,
        },
      });
      ownedTargetResources.push(identity);
      // Persist newly created target-RP resource ownership immediately before LRO polling so interrupted runs can still purge (#4267)!
      saveLedger(options.workDir, ledger);
    }
  }

  const shouldPoll = input.pollLro !== false && !expectError && method !== "GET";
  const maxPollAttempts = input.maxPollAttempts ?? 45;
  const defaultPollIntervalMs = input.pollIntervalMs ?? 2000;
  const maxPollDurationMs = input.maxPollDurationMs ?? 15 * 60_000;
  const pollDeadlineMs = Date.now() + maxPollDurationMs;

  const lroInit =
    initialExchange.response.status >= 200 &&
    initialExchange.response.status < 300 &&
    method !== "GET"
      ? detectInitialLroSignals(contract, initialExchange)
      : { signals: [] };

  const observedLro: ObservedLroBehavior = {
    detected: lroInit.signals.length > 0,
    detectionSignals: lroInit.signals,
    pollCount: 0,
    completionStatus: lroInit.signals.length > 0 ? "timed_out" : "not-applicable",
    pollingHeaderUsed: lroInit.pollingHeaderUsed,
    terminalProvisioningState: extractProvisioningState(initialExchange.response.body),
    finalResultSource: initialExchange.response.body !== undefined ? "initial-body" : "none",
  };

  let lroFailureReason: string | undefined;
  let paginationCompletedCleanly = true;
  let paginationFailureReason: string | undefined;
  let followUpException: unknown;

  try {
    if (observedLro.detected) {
      if (!shouldPoll || !lroInit.pollTargetUrl) {
        observedLro.completionStatus = "timed_out";
        lroFailureReason = !shouldPoll
          ? "LRO detected on wire, but polling was disabled (--no-poll)."
          : "LRO detected on wire, but no polling target URL could be determined.";
      } else {
        let currentPollUrl = resolvePollingUrl(ledger.armBaseUrl, lroInit.pollTargetUrl);
        let lastWaitHeaders = initialExchange.response.headers;
        let pollFinished = false;
        let monitorDeliveredPayload = false;

        for (let attempt = 1; attempt <= maxPollAttempts; attempt++) {
          const waitMs = parseRetryAfterMs(lastWaitHeaders, defaultPollIntervalMs);
          if (Date.now() + waitMs > pollDeadlineMs) {
            lroFailureReason = `LRO polling exceeded maxPollDurationMs (${maxPollDurationMs}ms) while honoring Retry-After (${waitMs}ms).`;
            break;
          }
          if (waitMs > 0) {
            await delay(waitMs);
          }

          const pollExchange = await sendRawHttpExchange({
            step: "poll",
            method: "GET",
            url: currentPollUrl,
            bearerToken: token,
            extraSensitiveHeaders: secretHeaderNames,
            safetyContext,
          });
          exchanges.push(pollExchange);
          observedLro.pollCount++;
          lastWaitHeaders = pollExchange.response.headers;

          // Honor Retry-After on transient 429 poll responses instead of immediately failing (#4190).
          if (pollExchange.response.status === 429) {
            continue;
          }

          if (pollExchange.response.status >= 400) {
            pollFinished = true;
            observedLro.completionStatus = "failed";
            observedLro.terminalProvisioningState = "Failed";
            lroFailureReason = `LRO poll returned HTTP ${pollExchange.response.status}.`;
            break;
          }

          if (
            lroInit.pollingHeaderUsed === "azure-asyncoperation" ||
            lroInit.pollingHeaderUsed === "operation-location"
          ) {
            const monitorStatus = extractAsyncMonitorStatus(pollExchange.response.body);
            if (monitorStatus) {
              observedLro.terminalProvisioningState = monitorStatus;
            }
            if (monitorStatus && !isNonTerminalProvisioningState(monitorStatus)) {
              pollFinished = true;
              if (isFailedOrCanceledState(monitorStatus)) {
                observedLro.completionStatus = "failed";
                lroFailureReason = `LRO terminated with status "${monitorStatus}".`;
              } else {
                observedLro.completionStatus = "succeeded";
              }
              const bodyObj =
                pollExchange.response.body && typeof pollExchange.response.body === "object"
                  ? (pollExchange.response.body as Record<string, unknown>)
                  : undefined;
              if (bodyObj && (bodyObj.properties !== undefined || bodyObj.result !== undefined)) {
                monitorDeliveredPayload = true;
              }
              break;
            }
          } else if (lroInit.pollingHeaderUsed === "location") {
            if (pollExchange.response.headers.location) {
              currentPollUrl = resolvePollingUrl(
                ledger.armBaseUrl,
                pollExchange.response.headers.location,
              );
            }
            const pollProvState = extractProvisioningState(pollExchange.response.body);
            if (pollProvState) {
              observedLro.terminalProvisioningState = pollProvState;
            }
            if (
              pollExchange.response.status !== 202 &&
              !isNonTerminalProvisioningState(pollProvState)
            ) {
              pollFinished = true;
              const termState =
                pollProvState ?? (pollExchange.response.status < 300 ? "Succeeded" : "Failed");
              observedLro.terminalProvisioningState = termState;
              if (pollExchange.response.status >= 300 || isFailedOrCanceledState(termState)) {
                observedLro.completionStatus = "failed";
                lroFailureReason = `Location LRO completed with status ${pollExchange.response.status} (${termState}).`;
              } else {
                observedLro.completionStatus = "succeeded";
              }
              observedLro.finalResultSource =
                pollExchange.response.body !== undefined ? "location-body" : "none";
              break;
            }
          } else if (lroInit.pollingHeaderUsed === "resource-get") {
            const provState = extractProvisioningState(pollExchange.response.body);
            observedLro.terminalProvisioningState = provState;
            if (!isNonTerminalProvisioningState(provState)) {
              pollFinished = true;
              const termState = provState ?? "Succeeded";
              if (isFailedOrCanceledState(termState)) {
                observedLro.completionStatus = "failed";
                lroFailureReason = `Resource provisioning terminated with state "${provState}".`;
              } else {
                observedLro.completionStatus = "succeeded";
              }
              observedLro.finalResultSource = "final-resource-get";
              break;
            }
          }
        }

        if (!pollFinished) {
          observedLro.completionStatus = "timed_out";
          lroFailureReason ??= `LRO did not reach a terminal state within ${maxPollAttempts} poll attempts.`;
        }

        if (
          pollFinished &&
          observedLro.completionStatus === "succeeded" &&
          (lroInit.pollingHeaderUsed === "azure-asyncoperation" ||
            lroInit.pollingHeaderUsed === "operation-location")
        ) {
          if (method === "PUT" || method === "PATCH") {
            const finalGet = await sendRawHttpExchange({
              step: "final-get",
              method: "GET",
              url: targetUrl,
              bearerToken: token,
              extraSensitiveHeaders: secretHeaderNames,
              safetyContext,
            });
            exchanges.push(finalGet);
            const finalProv = extractProvisioningState(finalGet.response.body);
            if (finalProv) {
              observedLro.terminalProvisioningState = finalProv;
            }
            observedLro.finalResultSource = "final-resource-get";
            if (
              finalGet.response.status < 200 ||
              finalGet.response.status >= 300 ||
              isNonTerminalProvisioningState(finalProv) ||
              isFailedOrCanceledState(finalProv)
            ) {
              observedLro.completionStatus = "failed";
              lroFailureReason = `Final resource GET failed with HTTP ${finalGet.response.status}${finalProv ? ` (${finalProv})` : ""}.`;
            }
          } else if (method === "POST") {
            const declaresLocationFinalState =
              contract.lroFinalStateVia?.toLowerCase() === "location";
            const locationHeaderUrl =
              initialExchange.response.headers.location ?? lastWaitHeaders.location;

            if (declaresLocationFinalState && locationHeaderUrl) {
              const locUrl = resolvePollingUrl(ledger.armBaseUrl, locationHeaderUrl);
              const locGet = await sendRawHttpExchange({
                step: "final-get",
                method: "GET",
                url: locUrl,
                bearerToken: token,
                extraSensitiveHeaders: secretHeaderNames,
                safetyContext,
              });
              exchanges.push(locGet);
              observedLro.finalResultSource =
                locGet.response.body !== undefined ? "location-body" : "none";
              if (locGet.response.status < 200 || locGet.response.status >= 300) {
                observedLro.completionStatus = "failed";
                lroFailureReason = `POST Location final-result GET failed with HTTP ${locGet.response.status}.`;
              }
            } else if (monitorDeliveredPayload) {
              observedLro.finalResultSource = "status-monitor-body";
            } else if (locationHeaderUrl) {
              const locUrl = resolvePollingUrl(ledger.armBaseUrl, locationHeaderUrl);
              const locGet = await sendRawHttpExchange({
                step: "final-get",
                method: "GET",
                url: locUrl,
                bearerToken: token,
                extraSensitiveHeaders: secretHeaderNames,
                safetyContext,
              });
              exchanges.push(locGet);
              observedLro.finalResultSource =
                locGet.response.body !== undefined ? "location-body" : "none";
              if (locGet.response.status < 200 || locGet.response.status >= 300) {
                observedLro.completionStatus = "failed";
                lroFailureReason = `POST Location final-result GET failed with HTTP ${locGet.response.status}.`;
              }
            } else {
              observedLro.finalResultSource = "none";
            }
          } else if (method === "DELETE") {
            observedLro.finalResultSource = "none";
          }
        }
      }
    }

    // Traverse all nextLink continuation pages with cycle & maxPages bounds (#15 / #16).
    const maxPages = input.maxPaginationPages ?? 25;
    const visitedNextLinks = new Set<string>([targetUrl]);
    let currentPageExchange = initialExchange;
    let pagesFetched = 1;
    const pagingHint = contract.pageable ?? contract.inferredPagination;

    while (
      input.followNextLink !== false &&
      !expectError &&
      method === "GET" &&
      currentPageExchange.response.status === 200 &&
      currentPageExchange.response.body &&
      typeof currentPageExchange.response.body === "object"
    ) {
      const nextLinkField = pagingHint?.nextLinkName ?? "nextLink";
      const nextLinkVal = nextLinkField
        ? (currentPageExchange.response.body as Record<string, unknown>)[nextLinkField]
        : undefined;
      if (typeof nextLinkVal !== "string" || nextLinkVal.length === 0) {
        break;
      }
      const resolvedNext = resolvePollingUrl(ledger.armBaseUrl, nextLinkVal);
      if (visitedNextLinks.has(resolvedNext)) {
        paginationCompletedCleanly = false;
        paginationFailureReason = `Pagination cycle detected on nextLink: ${resolvedNext}`;
        break;
      }
      if (pagesFetched >= maxPages) {
        paginationCompletedCleanly = false;
        paginationFailureReason = `Pagination exceeded maxPaginationPages (${maxPages}) without exhausting nextLink.`;
        break;
      }
      visitedNextLinks.add(resolvedNext);
      const nextPageExchange = await sendRawHttpExchange({
        step: "next-page",
        method: "GET",
        url: resolvedNext,
        bearerToken: token,
        extraSensitiveHeaders: secretHeaderNames,
        safetyContext,
      });
      exchanges.push(nextPageExchange);
      pagesFetched++;
      currentPageExchange = nextPageExchange;
      if (nextPageExchange.response.status < 200 || nextPageExchange.response.status >= 300) {
        paginationCompletedCleanly = false;
        paginationFailureReason = `Continuation page ${pagesFetched} failed with HTTP ${nextPageExchange.response.status}.`;
        break;
      }
    }
  } catch (err) {
    // Persist partial trace & failure status if any follow-up poll/final-get/nextLink throws or fails safety check (#4267)!
    followUpException = err;
    const errMsg = err instanceof Error ? err.message : String(err);
    if (observedLro.detected && observedLro.completionStatus !== "succeeded") {
      observedLro.completionStatus = "failed";
      lroFailureReason = errMsg;
    } else {
      paginationCompletedCleanly = false;
      paginationFailureReason = errMsg;
    }
  }

  const pagingHint = contract.pageable ?? contract.inferredPagination;

  const { requestErrors: requestSchemaErrors, responseErrors: responseSchemaErrors } =
    await runTypeSpecLiveValidation(
      contract.typespecProjectDir,
      contract.apiVersion,
      contract.operationId,
      initialExchange,
    );

  const appendUniqueResponseErrors = (errs: typeof responseSchemaErrors) => {
    for (const err of errs) {
      if (
        !responseSchemaErrors.some(
          (existing) =>
            existing.code === err.code &&
            existing.path === err.path &&
            existing.message === err.message,
        )
      ) {
        responseSchemaErrors.push(err);
      }
    }
  };

  const lastPollExchange = [...exchanges].reverse().find((e) => e.step === "poll");
  const hasSeparateFinalGet = exchanges.some((e) => e.step === "final-get");

  // Validate terminal resource/result GETs (PUT/PATCH/POST final-get, or direct Location/resource-get terminal poll)
  // AND every pagination next-page exchange (#17 / #18).
  for (const ex of exchanges.slice(1)) {
    const isDirectResourceOrLocationTerminalPoll =
      !hasSeparateFinalGet &&
      ex === lastPollExchange &&
      observedLro.completionStatus === "succeeded" &&
      (lroInit.pollingHeaderUsed === "location" || lroInit.pollingHeaderUsed === "resource-get");

    if (
      ex.step === "final-get" ||
      ex.step === "next-page" ||
      isDirectResourceOrLocationTerminalPoll
    ) {
      const followCheck = await runTypeSpecLiveValidation(
        contract.typespecProjectDir,
        contract.apiVersion,
        contract.operationId,
        ex,
      );
      appendUniqueResponseErrors(followCheck.responseErrors);
    }
  }

  // Validate LRO results on completed monitored POSTs whenever no separate final GET occurred
  // (including when the monitor returned only { status: "Succeeded" } and omitted a required logical result: #4241)!
  let missingRequiredMonitorResult = false;
  if (
    !hasSeparateFinalGet &&
    lastPollExchange &&
    observedLro.completionStatus === "succeeded" &&
    (observedLro.finalResultSource === "status-monitor-body" ||
      (method === "POST" &&
        (lroInit.pollingHeaderUsed === "azure-asyncoperation" ||
          lroInit.pollingHeaderUsed === "operation-location")))
  ) {
    const monitorIssues = await runTypeSpecMonitorResultValidation(
      contract.typespecProjectDir,
      contract.apiVersion,
      contract.operationId,
      lastPollExchange.response.body,
    );
    appendUniqueResponseErrors(monitorIssues);
    if (monitorIssues.some((e) => e.code === "MISSING_LRO_MONITOR_RESULT")) {
      missingRequiredMonitorResult = true;
    }
  }

  const normalizedTargetPath = stripConfiguredArmBasePath(targetUrl, ledger.armBaseUrl)
    .replace(/\/+$/, "")
    .toLowerCase();

  // Auto-attach saved priorPutBody strictly by exact resource path so GET of resource B never compares against resource A (#7963).
  const effectivePriorPutBody =
    input.priorPutBody ??
    (method === "GET" && !contract.pageable && !contract.inferredPagination
      ? runtimeState.putBodiesByResourceType[`path:${normalizedTargetPath}`]
      : undefined);

  const discrepancies = analyzeBehavioralDiscrepancies({
    contract,
    expectError,
    exchanges,
    observedLro,
    requestSchemaErrors,
    responseSchemaErrors,
    priorPutBody: effectivePriorPutBody,
  });

  const isInitial2xx =
    initialExchange.response.status >= 200 && initialExchange.response.status < 300;
  const initialWriteTerminalState =
    method !== "GET" ? extractProvisioningState(initialExchange.response.body) : undefined;
  const isImmediateFailedWrite = isFailedOrCanceledState(initialWriteTerminalState);

  const lroCompletedOk = !observedLro.detected || observedLro.completionStatus === "succeeded";
  const probeSucceeded = expectError
    ? followUpException === undefined &&
      initialExchange.response.status >= 400 &&
      initialExchange.response.status < 500
    : followUpException === undefined &&
      isInitial2xx &&
      !isImmediateFailedWrite &&
      !missingRequiredMonitorResult &&
      lroCompletedOk &&
      paginationCompletedCleanly;

  const failureReason = !probeSucceeded
    ? ((isImmediateFailedWrite
        ? `Operation returned HTTP ${initialExchange.response.status} with terminal provisioningState "${initialWriteTerminalState}".`
        : undefined) ??
      (missingRequiredMonitorResult
        ? `Monitored POST LRO completed without delivering declared final result payload.`
        : undefined) ??
      lroFailureReason ??
      paginationFailureReason ??
      `HTTP ${initialExchange.response.status}: ${JSON.stringify(initialExchange.response.body ?? initialExchange.response.rawTextSnippet ?? "").slice(0, 240)}`)
    : undefined;

  // Record observed path slots, PUT bodies, and List child item names into runtimeState on positive success.
  if (!expectError && probeSucceeded) {
    const boundSlots = extractPathSlotsFromUrl(contract.pathTemplate, targetUrl, ledger.armBaseUrl);
    for (const [k, v] of Object.entries(boundSlots)) {
      const lowerK = k.toLowerCase();
      if (
        lowerK !== "subscriptionid" &&
        lowerK !== "resourcegroupname" &&
        lowerK !== "resourcegroup" &&
        lowerK !== "scope"
      ) {
        runtimeState.pathSlotValues[k] = v;
      }
    }

    if (
      method === "PUT" &&
      input.body &&
      typeof input.body === "object" &&
      !Array.isArray(input.body)
    ) {
      const bodyRecord = input.body as Record<string, unknown>;
      runtimeState.putBodiesByResourceType[`path:${normalizedTargetPath}`] = bodyRecord;
      runtimeState.putBodiesByResourceType[contract.resourceType] = bodyRecord;
    }

    if (method === "GET") {
      const itemField = pagingHint?.itemName || "value";
      const discoveredNames: string[] = [];
      for (const ex of exchanges) {
        if (
          (ex.step === "initial" || ex.step === "next-page") &&
          ex.response.status === 200 &&
          ex.response.body &&
          typeof ex.response.body === "object" &&
          !Array.isArray(ex.response.body)
        ) {
          const arr = (ex.response.body as Record<string, unknown>)[itemField];
          if (Array.isArray(arr)) {
            for (const item of arr) {
              if (
                item &&
                typeof item === "object" &&
                typeof (item as Record<string, unknown>).name === "string"
              ) {
                const rawName = String((item as Record<string, unknown>).name);
                const leafName = rawName.includes("/") ? rawName.split("/").pop()! : rawName;
                if (leafName && !discoveredNames.includes(leafName)) {
                  discoveredNames.push(leafName);
                }
              }
            }
          }
        }
      }
      if (discoveredNames.length > 0) {
        runtimeState.listItemNamesByResourceType[contract.resourceType] = discoveredNames;
      }
    }
  }

  const secretQueryParamNames = contract.parameters
    .filter((p) => p.in === "query" && p.secretCandidate)
    .map((p) => p.name);
  const secretPathSlotNames = contract.parameters
    .filter((p) => p.in === "path" && p.secretCandidate)
    .map((p) => p.name);
  if (secretQueryParamNames.length > 0 || secretPathSlotNames.length > 0) {
    for (const ex of exchanges) {
      ex.request.url = sanitizeUrlSecretParameters(ex.request.url, {
        armBaseUrl: ledger.armBaseUrl,
        secretQueryParamNames,
        secretPathTemplate: contract.pathTemplate,
        secretPathSlotNames,
      });
    }
  }

  const sequence = nextTraceSequence(options.workDir);
  const scenario = input.scenario ?? (expectError ? "negative" : "default");
  const trace: ProbeTrace = {
    sequence,
    operationId: contract.operationId,
    scenario,
    expectError,
    probeSucceeded,
    ...(failureReason ? { failureReason } : {}),
    typespecProjectDir: contract.typespecProjectDir,
    sourceLocation: contract.sourceLocation,
    apiVersion: contract.apiVersion,
    observedLro,
    exchanges,
    requestSchemaErrors,
    responseSchemaErrors,
    discrepancies,
  };

  const traceFile = saveProbeTrace(options.workDir, trace);

  // Update coverage entry in ledger.
  const cov = ledger.coverage[contract.operationId];
  cov.attempts += 1;
  cov.lastHttpStatus = initialExchange.response.status;
  cov.traceFiles.push(traceFile);
  cov.discrepancyCount += discrepancies.length;

  if (probeSucceeded) {
    // Only mark an operation covered once at least one non-negative scenario completes cleanly (#19–#22).
    // Negative pre-checks (`expectError: true`) retain their discrepancies in `discrepancyCount` & `traceFiles`
    // while keeping `cov.status` as `"pending"` until a positive probe succeeds!
    if (!expectError) {
      cov.status = cov.discrepancyCount > 0 ? "passed_with_mismatch" : "passed";
      cov.blockerReason = undefined;
    }
  } else if (!expectError && cov.status !== "passed" && cov.status !== "passed_with_mismatch") {
    cov.status = "failed_service_error";
    cov.blockerReason = failureReason;
  }

  saveLedger(options.workDir, ledger);
  if (followUpException !== undefined) {
    if (followUpException instanceof Error) {
      throw followUpException;
    }
    throw new Error(
      typeof followUpException === "string" ? followUpException : JSON.stringify(followUpException),
    );
  }
  return { trace, traceFile };
}
