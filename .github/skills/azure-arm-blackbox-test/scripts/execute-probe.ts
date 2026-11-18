import { setTimeout as delay } from "node:timers/promises";
import {
  analyzeBehavioralDiscrepancies,
  extractProvisioningState,
  isNonTerminalProvisioningState,
  runTypeSpecLiveValidation,
} from "./analyze-behavior.ts";
import {
  getArmBearerToken,
  sendRawHttpExchange,
  type SafetyGuardContext,
} from "./auth-and-http.ts";
import { loadLedger, nextTraceSequence, saveLedger, saveProbeTrace } from "./ledger-store.ts";
import type {
  ObservedLroBehavior,
  OperationContract,
  ProbeRequestInput,
  ProbeTrace,
  WireHttpExchange,
} from "./types.ts";

export interface ExecuteProbeOptions {
  workDir: string;
  input: ProbeRequestInput;
  bearerToken?: string;
}

function buildTargetUrl(
  armBaseUrl: string,
  pathOrUrl: string,
  apiVersion: string,
  extraQuery?: Record<string, string>,
): string {
  const base = armBaseUrl.replace(/\/+$/, "");
  const rawUrl = /^https?:\/\//i.test(pathOrUrl)
    ? pathOrUrl
    : `${base}${pathOrUrl.startsWith("/") ? "" : "/"}${pathOrUrl}`;
  const parsed = new URL(rawUrl);
  if (!parsed.searchParams.has("api-version") && apiVersion) {
    parsed.searchParams.set("api-version", apiVersion);
  }
  for (const [k, v] of Object.entries(extraQuery ?? {})) {
    parsed.searchParams.set(k, v);
  }
  return parsed.toString();
}

function resolvePollingUrl(armBaseUrl: string, headerVal: string): string {
  if (/^https?:\/\//i.test(headerVal)) {
    return headerVal;
  }
  const base = armBaseUrl.replace(/\/+$/, "");
  return `${base}${headerVal.startsWith("/") ? "" : "/"}${headerVal}`;
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

function parseRetryAfterMs(
  headers: Record<string, string>,
  fallbackMs: number,
  maxStepWaitMs = 15_000,
): number {
  const raw = headers["retry-after"];
  if (!raw) {
    return fallbackMs;
  }
  const seconds = Number(raw);
  if (Number.isFinite(seconds) && seconds >= 0) {
    return Math.min(Math.max(seconds * 1000, Math.min(fallbackMs, 250)), maxStepWaitMs);
  }
  return fallbackMs;
}

function extractResourceNameFromPath(urlStr: string): string | undefined {
  try {
    const pathname = decodeURIComponent(new URL(urlStr).pathname).replace(/\/+$/, "");
    const providerIdx = pathname.toLowerCase().lastIndexOf("/providers/");
    if (providerIdx === -1) {
      return undefined;
    }
    const after = pathname
      .slice(providerIdx + "/providers/".length)
      .split("/")
      .filter(Boolean);
    // [namespace, type, name, ...]
    if (after.length >= 3) {
      return after[2];
    }
    return undefined;
  } catch {
    return undefined;
  }
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
      (status === 201 && (contract.method === "POST" || contract.method === "DELETE")))
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
  });

  const ownedResourceNames = ledger.provisionedFixtures.map((f) => f.name);
  const safetyContext: SafetyGuardContext = {
    disposableRgName: ledger.disposableResourceGroup?.name,
    ownedResourceNames,
    allowDisposableRgLifecycle: false,
  };

  const method = input.method ?? contract.method;
  const targetUrl = buildTargetUrl(
    ledger.armBaseUrl,
    input.pathOrUrl,
    contract.apiVersion,
    input.query,
  );

  const exchanges: WireHttpExchange[] = [];
  const initialExchange = await sendRawHttpExchange({
    step: "initial",
    method,
    url: targetUrl,
    bearerToken: token,
    headers: input.headers,
    body: input.body,
    safetyContext,
  });
  exchanges.push(initialExchange);

  // Track created target-RP resource names inside our disposable RG so soft-delete purge is permitted for them.
  if (
    method === "PUT" &&
    initialExchange.response.status >= 200 &&
    initialExchange.response.status < 300
  ) {
    const resName = extractResourceNameFromPath(targetUrl);
    if (resName && !ledger.provisionedFixtures.some((f) => f.name === resName)) {
      ledger.provisionedFixtures.push({
        kind: "target-rp-resource",
        name: resName,
        resourceId: new URL(targetUrl).pathname,
        provisionedAt: new Date().toISOString(),
      });
    }
  }

  const expectError = Boolean(input.expectError);
  const shouldPoll = input.pollLro !== false && !expectError && method !== "GET";
  const maxPollAttempts = input.maxPollAttempts ?? 45;
  const defaultPollIntervalMs = input.pollIntervalMs ?? 2000;

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
    pollingHeaderUsed: lroInit.pollingHeaderUsed,
    terminalProvisioningState: extractProvisioningState(initialExchange.response.body),
    finalResultSource: initialExchange.response.body !== undefined ? "initial-body" : "none",
  };

  if (shouldPoll && observedLro.detected && lroInit.pollTargetUrl) {
    let currentPollUrl = resolvePollingUrl(ledger.armBaseUrl, lroInit.pollTargetUrl);
    let lastWaitHeaders = initialExchange.response.headers;
    let pollFinished = false;
    let monitorDeliveredPayload = false;

    for (let attempt = 1; attempt <= maxPollAttempts; attempt++) {
      const waitMs = parseRetryAfterMs(
        lastWaitHeaders,
        defaultPollIntervalMs,
        Math.max(defaultPollIntervalMs * 5, 15_000),
      );
      if (waitMs > 0) {
        await delay(waitMs);
      }

      const pollExchange = await sendRawHttpExchange({
        step: "poll",
        method: "GET",
        url: currentPollUrl,
        bearerToken: token,
        safetyContext,
      });
      exchanges.push(pollExchange);
      observedLro.pollCount++;
      lastWaitHeaders = pollExchange.response.headers;

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
        if (pollExchange.response.status !== 202) {
          pollFinished = true;
          observedLro.terminalProvisioningState =
            extractProvisioningState(pollExchange.response.body) ??
            (pollExchange.response.status < 300 ? "Succeeded" : "Failed");
          observedLro.finalResultSource =
            pollExchange.response.body !== undefined ? "location-body" : "none";
          break;
        }
      } else if (lroInit.pollingHeaderUsed === "resource-get") {
        const provState = extractProvisioningState(pollExchange.response.body);
        observedLro.terminalProvisioningState = provState;
        if (!isNonTerminalProvisioningState(provState)) {
          pollFinished = true;
          observedLro.finalResultSource = "final-resource-get";
          break;
        }
      }
    }

    if (
      pollFinished &&
      observedLro.terminalProvisioningState?.toLowerCase() === "succeeded" &&
      (lroInit.pollingHeaderUsed === "azure-asyncoperation" ||
        lroInit.pollingHeaderUsed === "operation-location")
    ) {
      if (method === "PUT" || method === "PATCH") {
        const finalGet = await sendRawHttpExchange({
          step: "final-get",
          method: "GET",
          url: targetUrl,
          bearerToken: token,
          safetyContext,
        });
        exchanges.push(finalGet);
        observedLro.terminalProvisioningState =
          extractProvisioningState(finalGet.response.body) ?? observedLro.terminalProvisioningState;
        observedLro.finalResultSource = "final-resource-get";
      } else if (method === "POST") {
        if (monitorDeliveredPayload) {
          observedLro.finalResultSource = "status-monitor-body";
        } else if (initialExchange.response.headers.location) {
          const locUrl = resolvePollingUrl(
            ledger.armBaseUrl,
            initialExchange.response.headers.location,
          );
          const locGet = await sendRawHttpExchange({
            step: "final-get",
            method: "GET",
            url: locUrl,
            bearerToken: token,
            safetyContext,
          });
          exchanges.push(locGet);
          observedLro.finalResultSource =
            locGet.response.body !== undefined ? "location-body" : "none";
        } else {
          observedLro.finalResultSource = "none";
        }
      } else if (method === "DELETE") {
        observedLro.finalResultSource = "none";
      }
    }
  }

  // Optional nextLink pagination verification on GET list calls.
  if (
    input.followNextLink !== false &&
    !expectError &&
    method === "GET" &&
    initialExchange.response.status === 200 &&
    initialExchange.response.body &&
    typeof initialExchange.response.body === "object"
  ) {
    const nextLinkField = contract.pageable?.nextLinkName ?? "nextLink";
    const nextLinkVal = nextLinkField
      ? (initialExchange.response.body as Record<string, unknown>)[nextLinkField]
      : undefined;
    if (typeof nextLinkVal === "string" && nextLinkVal.length > 0) {
      const resolvedNext = resolvePollingUrl(ledger.armBaseUrl, nextLinkVal);
      const nextPageExchange = await sendRawHttpExchange({
        step: "next-page",
        method: "GET",
        url: resolvedNext,
        bearerToken: token,
        safetyContext,
      });
      exchanges.push(nextPageExchange);
    }
  }

  const { requestErrors: requestSchemaErrors, responseErrors: responseSchemaErrors } =
    await runTypeSpecLiveValidation(
      contract.typespecProjectDir,
      contract.apiVersion,
      contract.operationId,
      initialExchange,
    );

  // Also validate final-get response against the operation/resource GET TypeSpec model if applicable.
  const finalGetExchange = exchanges.find((ex) => ex.step === "final-get");
  if (finalGetExchange && (method === "PUT" || method === "PATCH")) {
    const finalCheck = await runTypeSpecLiveValidation(
      contract.typespecProjectDir,
      contract.apiVersion,
      contract.operationId,
      finalGetExchange,
    );
    for (const err of finalCheck.responseErrors) {
      if (
        !responseSchemaErrors.some(
          (existing) => existing.code === err.code && existing.message === err.message,
        )
      ) {
        responseSchemaErrors.push(err);
      }
    }
  }

  const discrepancies = analyzeBehavioralDiscrepancies({
    contract,
    expectError,
    exchanges,
    observedLro,
    requestSchemaErrors,
    responseSchemaErrors,
    priorPutBody: input.priorPutBody,
  });

  const sequence = nextTraceSequence(options.workDir);
  const scenario = input.scenario ?? (expectError ? "negative" : "default");
  const trace: ProbeTrace = {
    sequence,
    operationId: contract.operationId,
    scenario,
    expectError,
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

  const isSuccessStatus =
    initialExchange.response.status >= 200 && initialExchange.response.status < 300;
  const probeSucceeded = expectError
    ? initialExchange.response.status >= 400 && initialExchange.response.status < 500
    : isSuccessStatus;

  if (probeSucceeded) {
    // Only mark an operation covered once at least one non-negative scenario passes (unless negative was its only probe and already passed).
    if (!expectError) {
      cov.status = cov.discrepancyCount > 0 ? "passed_with_mismatch" : "passed";
      cov.blockerReason = undefined;
    } else if (cov.status === "pending") {
      // Negative pre-check succeeded, keep pending until positive call runs if this is GET, or keep note.
      if (discrepancies.length > 0) {
        cov.status = "passed_with_mismatch";
      }
    }
  } else if (cov.status !== "passed" && cov.status !== "passed_with_mismatch") {
    cov.status = "failed_service_error";
    cov.blockerReason = `HTTP ${initialExchange.response.status}: ${JSON.stringify(initialExchange.response.body ?? initialExchange.response.rawTextSnippet ?? "").slice(0, 240)}`;
  }

  saveLedger(options.workDir, ledger);
  return { trace, traceFile };
}
