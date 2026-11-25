import * as fs from "node:fs";
import * as path from "node:path";
import {
  findHeaderCaseInsensitive,
  safeDecodeUriSegment,
  stripConfiguredArmBasePath,
} from "./auth-and-http.ts";
import {
  GENERATED_EXAMPLES_DIRNAME,
  loadAllProbeTraces,
  loadLedger,
  saveLedger,
} from "./ledger-store.ts";
import { sanitizePayload, type SanitizeContext } from "./sanitize-example.ts";
import { loadProjectedTypeSpecService } from "./typespec-loader.ts";
import { validateExampleAgainstTypeSpec } from "./typespec-validator.ts";
import type {
  GeneratedExampleArtifact,
  OperationContract,
  ProbeTrace,
  WireHttpExchange,
} from "./types.ts";

export interface GenerateExamplesOptions {
  workDir: string;
  writeToSpec?: boolean;
  validateWithTypeSpec?: boolean;
}

export interface XMsExampleDocument {
  title: string;
  operationId: string;
  parameters: Record<string, unknown>;
  responses: Record<
    string,
    {
      headers?: Record<string, string>;
      body?: unknown;
    }
  >;
}

export interface ExampleOavCompleteness {
  observedStatusCodes: string[];
  missingDeclaredStatusCodes: string[];
  oavComplete: boolean;
  oavIssues: string[];
}

function extractPathParametersFromUrl(
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

  if (templateSegs.length !== actualSegs.length) {
    // Fallback regex matching when an x-ms-skip-url-encoding parameter spans slashes.
    const paramNames: string[] = [];
    const regexStr = cleanTemplate
      .split("/")
      .map((seg) => {
        const paramMatch = /^\{([^}]+)\}$/.exec(seg);
        if (paramMatch) {
          paramNames.push(paramMatch[1]);
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

  for (let i = 0; i < templateSegs.length; i++) {
    const paramMatch = /^\{([^}]+)\}$/.exec(templateSegs[i]);
    if (paramMatch) {
      extracted[paramMatch[1]] = safeDecodeUriSegment(actualSegs[i]);
    }
  }
  return extracted;
}

function sanitizeResponseBodyForStatus(
  contract: OperationContract,
  statusCode: string,
  body: unknown,
  sanitizeCtx: SanitizeContext,
): unknown {
  if (body === undefined) {
    return undefined;
  }
  if (contract.secretResponseStatuses?.includes(statusCode)) {
    if (typeof body === "string") {
      return "<redacted>";
    }
    return sanitizePayload(body, sanitizeCtx, undefined, "", undefined, [], true);
  }
  return sanitizePayload(body, sanitizeCtx);
}

function sanitizeSafeExampleStem(raw: string): string {
  const cleaned = raw.replace(/[^a-zA-Z0-9_-]/g, "_").replace(/^\.+/, "_");
  return cleaned || "operation";
}

function assertContainedFilePath(parentDir: string, candidateFile: string): void {
  const resolvedParent = path.resolve(parentDir);
  const resolvedChild = path.resolve(candidateFile);
  if (
    resolvedChild !== resolvedParent &&
    !resolvedChild.startsWith(`${resolvedParent}${path.sep}`)
  ) {
    throw new Error(
      `Refusing to write example path outside target directory "${resolvedParent}": "${resolvedChild}"`,
    );
  }
}

const CANONICAL_LRO_WIRE_HEADERS: ReadonlyArray<{ lower: string; canonical: string }> = [
  { lower: "azure-asyncoperation", canonical: "Azure-AsyncOperation" },
  { lower: "location", canonical: "Location" },
  { lower: "operation-location", canonical: "Operation-Location" },
  { lower: "retry-after", canonical: "Retry-After" },
];

const LRO_ALLOWED_2XX_BY_METHOD: Record<string, ReadonlySet<string>> = {
  POST: new Set(["200", "201", "202", "204"]),
  PATCH: new Set(["200", "201", "202"]),
  DELETE: new Set(["200", "202", "204"]),
  PUT: new Set(["200", "201", "202"]),
};

function isObservedLroCompletedCleanly(observedLro: ProbeTrace["observedLro"]): boolean {
  if (!observedLro.detected) {
    return false;
  }
  if (observedLro.completionStatus !== undefined) {
    return observedLro.completionStatus === "succeeded";
  }
  const term = observedLro.terminalProvisioningState ?? "";
  return !/^(failed|canceled|cancelled|creating|updating|deleting|provisioning|accepted|running|inprogress)$/i.test(
    term,
  );
}

function pickWireResponseHeaders(
  contract: OperationContract,
  statusCode: string,
  actualHeaders: Record<string, string>,
  sanitizeCtx: SanitizeContext,
  preserveWireLroHeaders = false,
): Record<string, string> | undefined {
  const declared = contract.declaredResponseHeaders[statusCode] ?? [];
  const picked: Record<string, string> = {};
  const pickedLower = new Set<string>();

  for (const headerName of declared) {
    const val = findHeaderCaseInsensitive(actualHeaders, headerName);
    if (val !== undefined) {
      picked[headerName] = String(sanitizePayload(val, sanitizeCtx, headerName));
      pickedLower.add(headerName.toLowerCase());
    }
  }

  if (preserveWireLroHeaders) {
    for (const lroHeader of CANONICAL_LRO_WIRE_HEADERS) {
      if (pickedLower.has(lroHeader.lower)) {
        continue;
      }
      const val = findHeaderCaseInsensitive(actualHeaders, lroHeader.lower);
      if (val !== undefined) {
        picked[lroHeader.canonical] = String(
          sanitizePayload(val, sanitizeCtx, lroHeader.canonical),
        );
        pickedLower.add(lroHeader.lower);
      }
    }
  }

  return Object.keys(picked).length > 0 ? picked : undefined;
}

export function evaluateExampleOavCompleteness(
  contract: OperationContract | undefined,
  exampleDoc: Pick<XMsExampleDocument, "responses">,
): ExampleOavCompleteness {
  const responses = exampleDoc.responses ?? {};
  const observedStatusCodes = Object.keys(responses).sort();
  if (!contract) {
    return {
      observedStatusCodes,
      missingDeclaredStatusCodes: [],
      oavComplete: false,
      oavIssues: ["Operation contract not found in coverage ledger."],
    };
  }

  const declared2xxCodes = contract.declaredStatusCodes
    .filter((code) => /^2\d\d$/.test(code))
    .sort();
  const missingDeclaredStatusCodes = declared2xxCodes.filter(
    (code) => responses[code] === undefined,
  );
  const undocumentedStatusCodes = observedStatusCodes.filter(
    (code) => !contract.declaredStatusCodes.includes(code),
  );

  const oavIssues: string[] = [];
  if (missingDeclaredStatusCodes.length > 0) {
    oavIssues.push(
      `Live wire observed [${observedStatusCodes.join(", ")}], missing declared 2xx status code(s) [${missingDeclaredStatusCodes.join(", ")}] required by OAV111 (RESPONSE_STATUS_CODE_NOT_IN_EXAMPLE).`,
    );
  }
  if (undocumentedStatusCodes.length > 0) {
    oavIssues.push(
      `Live wire observed undocumented status code(s) [${undocumentedStatusCodes.join(", ")}] not declared in TypeSpec [${declared2xxCodes.join(", ")}].`,
    );
  }

  if (contract.isLroDeclared) {
    const allowedLroSet = LRO_ALLOWED_2XX_BY_METHOD[contract.method.toUpperCase()];
    if (allowedLroSet) {
      const disallowedLroCodes = observedStatusCodes.filter(
        (code) => /^2\d\d$/.test(code) && !allowedLroSet.has(code),
      );
      if (disallowedLroCodes.length > 0) {
        oavIssues.push(
          `Response status code(s) [${disallowedLroCodes.join(", ")}] violate OAV LRO_RESPONSE_CODE for ${contract.method} LRO.`,
        );
      }
    }

    const methodUpper = contract.method.toUpperCase();
    if (
      (methodUpper === "POST" || methodUpper === "PATCH" || methodUpper === "DELETE") &&
      responses["202"] !== undefined
    ) {
      const headers202 = responses["202"].headers ?? {};
      const locVal = findHeaderCaseInsensitive(headers202, "location");
      const asyncVal = findHeaderCaseInsensitive(headers202, "azure-asyncoperation");
      const hasArmLroHeader = Boolean(
        (locVal && locVal.trim().length > 0) || (asyncVal && asyncVal.trim().length > 0),
      );
      if (!hasArmLroHeader) {
        oavIssues.push(
          'Response "202" is missing non-empty Location or Azure-AsyncOperation header required by OAV LRO_RESPONSE_HEADER.',
        );
      }
    }
  }

  return {
    observedStatusCodes,
    missingDeclaredStatusCodes,
    oavComplete: oavIssues.length === 0,
    oavIssues,
  };
}

export function buildXMsExampleFromTrace(
  contract: OperationContract,
  trace: ProbeTrace,
  sanitizeCtx: SanitizeContext,
): XMsExampleDocument {
  const initial: WireHttpExchange | undefined = trace.exchanges[0];
  if (!initial) {
    throw new Error(`Trace for ${contract.operationId} contains no HTTP exchanges.`);
  }

  const parsedUrl = new URL(initial.request.url);
  const rawPathParams = extractPathParametersFromUrl(
    contract.pathTemplate,
    initial.request.url,
    sanitizeCtx.armBaseUrl,
  );

  const parameters: Record<string, unknown> = {};
  for (const paramSpec of contract.parameters) {
    if (paramSpec.in === "path") {
      const matchedVal =
        rawPathParams[paramSpec.name] ??
        Object.entries(rawPathParams).find(
          ([k]) => k.toLowerCase() === paramSpec.name.toLowerCase(),
        )?.[1];
      if (matchedVal !== undefined) {
        parameters[paramSpec.name] = sanitizePayload(matchedVal, sanitizeCtx, paramSpec.name);
      }
    } else if (paramSpec.in === "query") {
      const queryVal = parsedUrl.searchParams.get(paramSpec.name);
      if (queryVal !== null) {
        parameters[paramSpec.name] = sanitizePayload(queryVal, sanitizeCtx, paramSpec.name);
      }
    } else if (paramSpec.in === "header") {
      const headerVal = findHeaderCaseInsensitive(initial.request.headers, paramSpec.name);
      if (headerVal !== undefined && paramSpec.name.toLowerCase() !== "authorization") {
        parameters[paramSpec.name] = sanitizePayload(headerVal, sanitizeCtx, paramSpec.name);
      }
    } else if (paramSpec.in === "body" && initial.request.body !== undefined) {
      parameters[paramSpec.name] = sanitizePayload(
        initial.request.body,
        sanitizeCtx,
        paramSpec.secretCandidate ? paramSpec.name : undefined,
        "",
        undefined,
        [],
        Boolean(paramSpec.secretCandidate),
      );
    }
  }

  // Ensure api-version is always populated when present on URL.
  if (parameters["api-version"] === undefined && parsedUrl.searchParams.has("api-version")) {
    parameters["api-version"] = parsedUrl.searchParams.get("api-version")!;
  }

  const responses: XMsExampleDocument["responses"] = {};
  const initialCode = String(initial.response.status);
  const finalGet = [...trace.exchanges].reverse().find((ex) => ex.step === "final-get");
  const lastPoll = [...trace.exchanges].reverse().find((ex) => ex.step === "poll");

  const initialHeaders = pickWireResponseHeaders(
    contract,
    initialCode,
    initial.response.headers,
    sanitizeCtx,
    trace.observedLro.detected && (initialCode === "201" || initialCode === "202"),
  );
  responses[initialCode] = {
    ...(initialHeaders ? { headers: initialHeaders } : {}),
    ...(initial.response.body !== undefined
      ? {
          body: sanitizeResponseBodyForStatus(
            contract,
            initialCode,
            initial.response.body,
            sanitizeCtx,
          ),
        }
      : {}),
  };

  // Pure wire-truth LRO stitching: emit a terminal response ONLY when an LRO actually ran
  // and completed cleanly on the wire, and a real terminal operation exchange/payload was observed.
  // Never synthesize or clone un-observed 2xx status codes, headers, or bodies.
  if (isObservedLroCompletedCleanly(trace.observedLro)) {
    const canUseLastPollAsTerminal =
      (trace.observedLro.pollingHeaderUsed === "location" ||
        trace.observedLro.pollingHeaderUsed === "resource-get") &&
      lastPoll !== undefined &&
      lastPoll.response.status >= 200 &&
      lastPoll.response.status < 300 &&
      lastPoll.response.status !== 202 &&
      (contract.declaredStatusCodes.includes(String(lastPoll.response.status)) ||
        !contract.isLroDeclared);

    const terminalWireExchange =
      finalGet && finalGet.response.status >= 200 && finalGet.response.status < 300
        ? finalGet
        : canUseLastPollAsTerminal
          ? lastPoll
          : undefined;

    if (terminalWireExchange) {
      const finalCode = String(terminalWireExchange.response.status);
      const finalHeaders = pickWireResponseHeaders(
        contract,
        finalCode,
        terminalWireExchange.response.headers,
        sanitizeCtx,
        false,
      );
      responses[finalCode] = {
        ...(finalHeaders ? { headers: finalHeaders } : {}),
        ...(terminalWireExchange.response.body !== undefined
          ? {
              body: sanitizeResponseBodyForStatus(
                contract,
                finalCode,
                terminalWireExchange.response.body,
                sanitizeCtx,
              ),
            }
          : {}),
      };
    } else if (
      contract.method === "POST" &&
      trace.observedLro.finalResultSource === "status-monitor-body" &&
      lastPoll &&
      lastPoll.response.status === 200 &&
      contract.declaredStatusCodes.includes("200") &&
      lastPoll.response.body &&
      typeof lastPoll.response.body === "object"
    ) {
      const monitorObj = lastPoll.response.body as Record<string, unknown>;
      const extractedResult = monitorObj.result ?? monitorObj.properties;
      if (extractedResult !== undefined) {
        responses["200"] = {
          body: sanitizeResponseBodyForStatus(contract, "200", extractedResult, sanitizeCtx),
        };
      }
    }
  }

  const scenarioSuffix =
    trace.scenario && trace.scenario !== "default" ? ` (${trace.scenario})` : "";
  return {
    title: `${contract.operationId}${scenarioSuffix}`,
    operationId: contract.operationId,
    parameters,
    responses,
  };
}

export async function generateLiveExamples(
  options: GenerateExamplesOptions,
): Promise<GeneratedExampleArtifact[]> {
  if (options.writeToSpec && options.validateWithTypeSpec === false) {
    throw new Error(
      "Cannot disable TypeSpec validation (validateWithTypeSpec: false) when writeToSpec is enabled.",
    );
  }
  const ledger = loadLedger(options.workDir);
  const allTraces = loadAllProbeTraces(options.workDir);

  // Group completed, successful positive traces by (operationId, scenario), keeping the latest successful trace (#19 / #20).
  const selectedTraces = new Map<string, ProbeTrace>();
  for (const trace of allTraces) {
    if (trace.expectError) {
      continue;
    }
    if (trace.probeSucceeded === false) {
      continue;
    }
    if (
      trace.observedLro.detected &&
      trace.observedLro.completionStatus !== undefined &&
      trace.observedLro.completionStatus !== "succeeded"
    ) {
      continue;
    }
    const initial = trace.exchanges[0];
    if (!initial || initial.response.status < 200 || initial.response.status >= 300) {
      continue;
    }
    selectedTraces.set(`${trace.operationId}::${trace.scenario}`, trace);
  }

  const scratchExamplesDir = path.join(
    options.workDir,
    GENERATED_EXAMPLES_DIRNAME,
    ledger.apiVersion,
  );
  fs.mkdirSync(scratchExamplesDir, { recursive: true });

  const service =
    options.validateWithTypeSpec !== false
      ? await loadProjectedTypeSpecService(ledger.typespecProjectDir, ledger.apiVersion)
      : undefined;

  const artifacts: GeneratedExampleArtifact[] = [];

  for (const trace of selectedTraces.values()) {
    const contract = ledger.operations[trace.operationId];
    if (!contract) {
      continue;
    }

    const sanitizeCtx: SanitizeContext = {
      subscriptionId: ledger.subscriptionId,
      disposableRgName: ledger.disposableResourceGroup?.name,
      armBaseUrl: ledger.armBaseUrl,
      allowedArmOrigins: ledger.allowedArmOrigins,
      extraSecretPropertyPaths: contract.secretProperties,
      secretQueryParamNames: contract.parameters
        .filter((p) => p.in === "query" && p.secretCandidate)
        .map((p) => p.name),
      secretPathTemplate: contract.pathTemplate,
      secretPathSlotNames: contract.parameters
        .filter((p) => p.in === "path" && p.secretCandidate)
        .map((p) => p.name),
      secretCycleRules: contract.secretCycleRules,
      secretConstraints: contract.secretConstraints,
    };

    const exampleDoc = buildXMsExampleFromTrace(contract, trace, sanitizeCtx);
    const safeOpStem = sanitizeSafeExampleStem(contract.operationId);
    const suffix =
      trace.scenario && trace.scenario !== "default"
        ? `_${trace.scenario.replace(/[^a-zA-Z0-9_-]/g, "")}`
        : "";
    const exampleName = `${safeOpStem}${suffix}`;
    const filename = `${exampleName}.json`;
    const scratchPath = path.join(scratchExamplesDir, filename);
    assertContainedFilePath(scratchExamplesDir, scratchPath);
    const serialized = `${JSON.stringify(exampleDoc, null, 2)}\n`;
    fs.writeFileSync(scratchPath, serialized, "utf8");

    let schemaValid = true;
    const schemaErrors: string[] = [];
    if (service) {
      try {
        const issues = validateExampleAgainstTypeSpec(service, contract.operationId, exampleDoc);
        if (issues.length > 0) {
          schemaValid = false;
          for (const issue of issues) {
            schemaErrors.push(`[${issue.code}] ${issue.message}`);
          }
        }
      } catch (err) {
        schemaValid = false;
        schemaErrors.push(err instanceof Error ? err.message : String(err));
      }
    }

    const oavCheck = evaluateExampleOavCompleteness(contract, exampleDoc);

    // Only promote into `<typespecProjectDir>/examples/` when both TypeSpec-valid and OAV-complete!
    const writtenSpecPaths: string[] = [];
    let specWriteSkippedReason: string | undefined;
    if (options.writeToSpec) {
      if (!schemaValid) {
        specWriteSkippedReason = `Skipped --write-to-spec (TypeSpec validation failed): ${schemaErrors.join("; ")}`;
      } else if (!oavCheck.oavComplete) {
        specWriteSkippedReason = `Skipped --write-to-spec (OAV incomplete): ${oavCheck.oavIssues.join(" ")}`;
      } else {
        const tspExDir = path.join(ledger.typespecProjectDir, "examples", ledger.apiVersion);
        fs.mkdirSync(tspExDir, { recursive: true });
        const tspExPath = path.join(tspExDir, filename);
        assertContainedFilePath(tspExDir, tspExPath);
        fs.writeFileSync(tspExPath, serialized, "utf8");
        writtenSpecPaths.push(tspExPath);
      }
    }

    const cov = ledger.coverage[contract.operationId];
    if (cov && !cov.generatedExamples.includes(scratchPath)) {
      cov.generatedExamples.push(scratchPath);
    }

    artifacts.push({
      operationId: contract.operationId,
      scenario: trace.scenario,
      exampleName,
      scratchPath,
      writtenSpecPaths,
      schemaValid,
      schemaErrors,
      observedStatusCodes: oavCheck.observedStatusCodes,
      missingDeclaredStatusCodes: oavCheck.missingDeclaredStatusCodes,
      oavComplete: oavCheck.oavComplete,
      oavIssues: oavCheck.oavIssues,
      ...(specWriteSkippedReason ? { specWriteSkippedReason } : {}),
    });
  }

  saveLedger(options.workDir, ledger);
  return artifacts;
}
