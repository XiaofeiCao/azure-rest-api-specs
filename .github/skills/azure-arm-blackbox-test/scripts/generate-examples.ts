import * as fs from "node:fs";
import * as path from "node:path";
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

interface XMsExampleDocument {
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

function extractPathParametersFromUrl(
  pathTemplate: string,
  actualUrl: string,
): Record<string, string> {
  const cleanTemplate = pathTemplate.split("?")[0].replace(/^\/+|\/+$/g, "");
  const actualPathname = new URL(actualUrl).pathname.replace(/^\/+|\/+$/g, "");

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
        extracted[name] = decodeURIComponent(match[idx + 1]);
      });
    }
    return extracted;
  }

  for (let i = 0; i < templateSegs.length; i++) {
    const paramMatch = /^\{([^}]+)\}$/.exec(templateSegs[i]);
    if (paramMatch) {
      extracted[paramMatch[1]] = decodeURIComponent(actualSegs[i]);
    }
  }
  return extracted;
}

function pickDeclaredHeaders(
  contract: OperationContract,
  statusCode: string,
  actualHeaders: Record<string, string>,
  sanitizeCtx: SanitizeContext,
): Record<string, string> | undefined {
  const declared = contract.declaredResponseHeaders[statusCode] ?? [];
  if (declared.length === 0) {
    return undefined;
  }
  const picked: Record<string, string> = {};
  for (const headerName of declared) {
    const val = actualHeaders[headerName.toLowerCase()];
    if (val !== undefined) {
      picked[headerName] = String(sanitizePayload(val, sanitizeCtx, headerName));
    }
  }
  return Object.keys(picked).length > 0 ? picked : undefined;
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
  const rawPathParams = extractPathParametersFromUrl(contract.pathTemplate, initial.request.url);

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
      const headerVal =
        initial.request.headers[paramSpec.name] ??
        initial.request.headers[paramSpec.name.toLowerCase()];
      if (headerVal !== undefined && paramSpec.name.toLowerCase() !== "authorization") {
        parameters[paramSpec.name] = sanitizePayload(headerVal, sanitizeCtx, paramSpec.name);
      }
    } else if (paramSpec.in === "body" && initial.request.body !== undefined) {
      parameters[paramSpec.name] = sanitizePayload(initial.request.body, sanitizeCtx);
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

  const initialHeaders = pickDeclaredHeaders(
    contract,
    initialCode,
    initial.response.headers,
    sanitizeCtx,
  );
  responses[initialCode] = {
    ...(initialHeaders ? { headers: initialHeaders } : {}),
    ...(initial.response.body !== undefined
      ? { body: sanitizePayload(initial.response.body, sanitizeCtx) }
      : {}),
  };

  // For LRO operations, include terminal response (EX-COVERAGE requires both initial and final responses on LROs).
  if (trace.observedLro.detected || contract.isLroDeclared) {
    if (finalGet && finalGet.response.status >= 200 && finalGet.response.status < 300) {
      const finalCode = String(finalGet.response.status);
      const finalHeaders = pickDeclaredHeaders(
        contract,
        finalCode,
        finalGet.response.headers,
        sanitizeCtx,
      );
      // Overwrite if initialCode === finalCode (e.g., PUT returned 200 Creating, then final GET returned 200 Succeeded),
      // or add alongside 201/202 when distinct!
      responses[finalCode] = {
        ...(finalHeaders ? { headers: finalHeaders } : {}),
        ...(finalGet.response.body !== undefined
          ? { body: sanitizePayload(finalGet.response.body, sanitizeCtx) }
          : {}),
      };
    } else if (
      contract.method === "DELETE" &&
      initialCode === "202" &&
      (contract.declaredStatusCodes.includes("200") || contract.declaredStatusCodes.includes("204"))
    ) {
      const terminalDeleteCode = contract.declaredStatusCodes.includes("200") ? "200" : "204";
      responses[terminalDeleteCode] = {};
    } else if (
      contract.method === "POST" &&
      initialCode === "202" &&
      lastPoll &&
      lastPoll.response.status === 200 &&
      contract.declaredStatusCodes.includes("200")
    ) {
      // Only include status-monitor body as 200 if operation expects a 200 body matching the final output;
      // for void POST LROs with 200/204 terminal status, omit monitor wrapper if finalResultSource === "none".
      if (
        trace.observedLro.finalResultSource === "location-body" &&
        lastPoll.response.body !== undefined
      ) {
        responses["200"] = {
          body: sanitizePayload(lastPoll.response.body, sanitizeCtx),
        };
      } else if (trace.observedLro.finalResultSource === "none") {
        responses["200"] = {};
      }
    }
  }

  // Populate remaining declared 2xx status codes required by OAV RESPONSE_STATUS_CODE_NOT_IN_EXAMPLE.
  for (const declaredCode of contract.declaredStatusCodes) {
    if (!declaredCode.startsWith("2") || responses[declaredCode] !== undefined) {
      continue;
    }
    const hasSchema = contract.declaredResponseHasSchema?.[declaredCode];
    if (hasSchema === false) {
      responses[declaredCode] = {};
    } else if (
      (contract.method === "PUT" || contract.method === "PATCH") &&
      (declaredCode === "200" || declaredCode === "201")
    ) {
      const donor = responses["200"] ?? responses["201"];
      if (donor?.body !== undefined) {
        responses[declaredCode] = { body: donor.body };
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
  const ledger = loadLedger(options.workDir);
  const allTraces = loadAllProbeTraces(options.workDir);

  // Group successful positive traces by (operationId, scenario), keeping the latest successful trace.
  const selectedTraces = new Map<string, ProbeTrace>();
  for (const trace of allTraces) {
    if (trace.expectError) {
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
      extraSecretPropertyPaths: contract.secretProperties,
    };

    const exampleDoc = buildXMsExampleFromTrace(contract, trace, sanitizeCtx);
    const suffix =
      trace.scenario && trace.scenario !== "default"
        ? `_${trace.scenario.replace(/[^a-zA-Z0-9_-]/g, "")}`
        : "";
    const exampleName = `${contract.operationId}${suffix}`;
    const filename = `${exampleName}.json`;
    const scratchPath = path.join(scratchExamplesDir, filename);
    const serialized = `${JSON.stringify(exampleDoc, null, 2)}\n`;
    fs.writeFileSync(scratchPath, serialized, "utf8");

    const writtenSpecPaths: string[] = [];
    if (options.writeToSpec) {
      const tspExDir = path.join(ledger.typespecProjectDir, "examples", ledger.apiVersion);
      fs.mkdirSync(tspExDir, { recursive: true });
      const tspExPath = path.join(tspExDir, filename);
      fs.writeFileSync(tspExPath, serialized, "utf8");
      writtenSpecPaths.push(tspExPath);
    }

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
    });
  }

  saveLedger(options.workDir, ledger);
  return artifacts;
}
