import { loadProjectedTypeSpecService } from "./typespec-loader.ts";
import {
  validateStatusMonitorResultAgainstTypeSpec,
  validateWireExchangeAgainstTypeSpec,
} from "./typespec-validator.ts";
import {
  DISCREPANCY_RULES,
  type BehavioralDiscrepancy,
  type ObservedLroBehavior,
  type OperationContract,
  type TypeSpecSchemaIssue,
  type WireHttpExchange,
} from "./types.ts";

const TERMINAL_PROVISIONING_STATES = new Set(["succeeded", "failed", "canceled", "cancelled"]);
const FAILED_OR_CANCELED_STATES = new Set(["failed", "canceled", "cancelled"]);

export function isFailedOrCanceledState(state: string | undefined): boolean {
  if (!state) {
    return false;
  }
  return FAILED_OR_CANCELED_STATES.has(state.trim().toLowerCase());
}

export function extractProvisioningState(body: unknown): string | undefined {
  if (!body || typeof body !== "object") {
    return undefined;
  }
  const record = body as Record<string, unknown>;
  const props = record.properties;
  if (props && typeof props === "object") {
    const ps = (props as Record<string, unknown>).provisioningState;
    if (typeof ps === "string" && ps.trim().length > 0) {
      return ps.trim();
    }
  }
  return undefined;
}

export function isNonTerminalProvisioningState(state: string | undefined): boolean {
  if (!state) {
    return false;
  }
  return !TERMINAL_PROVISIONING_STATES.has(state.toLowerCase());
}

export async function runTypeSpecLiveValidation(
  typespecProjectDir: string,
  apiVersion: string,
  operationId: string,
  exchange: WireHttpExchange,
): Promise<{
  requestErrors: TypeSpecSchemaIssue[];
  responseErrors: TypeSpecSchemaIssue[];
}> {
  try {
    const service = await loadProjectedTypeSpecService(typespecProjectDir, apiVersion);
    return validateWireExchangeAgainstTypeSpec(service, operationId, exchange);
  } catch (err) {
    return {
      requestErrors: [],
      responseErrors: [
        {
          code: "TYPESPEC_VALIDATION_ERROR",
          message: err instanceof Error ? err.message : String(err),
          path: "$",
          severity: "error",
        },
      ],
    };
  }
}

export async function runTypeSpecMonitorResultValidation(
  typespecProjectDir: string,
  apiVersion: string,
  operationId: string,
  monitorBody: unknown,
): Promise<TypeSpecSchemaIssue[]> {
  try {
    const service = await loadProjectedTypeSpecService(typespecProjectDir, apiVersion);
    return validateStatusMonitorResultAgainstTypeSpec(service, operationId, monitorBody);
  } catch (err) {
    return [
      {
        code: "TYPESPEC_VALIDATION_ERROR",
        message: err instanceof Error ? err.message : String(err),
        path: "$.monitor.result",
        severity: "error",
      },
    ];
  }
}

function getNestedValue(obj: unknown, dotPath: string): unknown {
  if (!obj || typeof obj !== "object") {
    return undefined;
  }
  const parts = dotPath.split(".");
  let current: unknown = obj;
  for (const part of parts) {
    if (!current || typeof current !== "object" || Array.isArray(current)) {
      return undefined;
    }
    current = (current as Record<string, unknown>)[part];
  }
  return current;
}

export interface AnalyzeBehaviorInput {
  contract: OperationContract;
  expectError: boolean;
  exchanges: WireHttpExchange[];
  observedLro: ObservedLroBehavior;
  requestSchemaErrors: TypeSpecSchemaIssue[];
  responseSchemaErrors: TypeSpecSchemaIssue[];
  priorPutBody?: unknown;
}

export function analyzeBehavioralDiscrepancies(
  input: AnalyzeBehaviorInput,
): BehavioralDiscrepancy[] {
  const {
    contract,
    expectError,
    exchanges,
    observedLro,
    requestSchemaErrors,
    responseSchemaErrors,
    priorPutBody,
  } = input;
  const discrepancies: BehavioralDiscrepancy[] = [];
  const initial = exchanges[0];
  if (!initial) {
    return discrepancies;
  }

  const terminalExchange =
    [...exchanges].reverse().find((ex) => ex.step === "final-get") ??
    (exchanges.length > 1 ? exchanges[exchanges.length - 1] : initial);

  const initialStatus = String(initial.response.status);
  const isInitial2xx = initial.response.status >= 200 && initial.response.status < 300;
  const isErrorStatus = initial.response.status >= 400;

  // 1. Undeclared LRO: spec says sync, live service behaves asynchronously.
  if (!expectError && isInitial2xx && !contract.isLroDeclared && observedLro.detected) {
    discrepancies.push({
      ruleId: DISCREPANCY_RULES.LRO_UNDECLARED,
      severity: "blocking",
      operationId: contract.operationId,
      sourceLocation: contract.sourceLocation,
      summary: `Live service executes ${contract.operationId} as a Long-Running Operation, but TypeSpec models it as synchronous.`,
      specExpectation: `Synchronous ${contract.method} operation in TypeSpec (no LRO metadata; declared statuses: ${contract.declaredStatusCodes.join(", ") || "none"}).`,
      actualWireBehavior: `Initial HTTP ${initial.response.status} exhibited LRO signals [${observedLro.detectionSignals.join(", ")}]; polled ${observedLro.pollCount} time(s) via ${observedLro.pollingHeaderUsed ?? "n/a"} to terminal state "${observedLro.terminalProvisioningState ?? "completed"}".`,
      evidence: {
        initialStatus: initial.response.status,
        pollingHeaders: {
          "azure-asyncoperation": initial.response.headers["azure-asyncoperation"],
          location: initial.response.headers.location,
          "operation-location": initial.response.headers["operation-location"],
          "retry-after": initial.response.headers["retry-after"],
        },
        detectionSignals: observedLro.detectionSignals,
        pollCount: observedLro.pollCount,
      },
    });
  }

  // 2. Declared LRO header / async contract drift.
  if (!expectError && isInitial2xx && contract.isLroDeclared) {
    const hasAsyncHeader = Boolean(
      initial.response.headers["azure-asyncoperation"] ||
      initial.response.headers.location ||
      initial.response.headers["operation-location"],
    );
    const initialProvState = extractProvisioningState(initial.response.body);

    if (
      (initial.response.status === 202 || isNonTerminalProvisioningState(initialProvState)) &&
      !hasAsyncHeader
    ) {
      discrepancies.push({
        ruleId: DISCREPANCY_RULES.LRO_HEADER_DRIFT,
        severity: "blocking",
        operationId: contract.operationId,
        summary: `Async response on ${contract.operationId} returned HTTP ${initial.response.status} (provisioningState=${initialProvState ?? "n/a"}) without any Azure-AsyncOperation or Location polling header.`,
        specExpectation: `ARM LRO responses returning 202 or non-terminal provisioningState must include Azure-AsyncOperation and/or Location polling headers matching declared response headers.`,
        actualWireBehavior: `HTTP ${initial.response.status} returned headers [${Object.keys(initial.response.headers).join(", ")}] with no polling URL.`,
        evidence: {
          initialStatus: initial.response.status,
          initialProvisioningState: initialProvState,
          declaredHeadersForStatus: contract.declaredResponseHeaders[initialStatus] ?? [],
        },
      });
    } else {
      const declaredHeaders = contract.declaredResponseHeaders[initialStatus] ?? [];
      const requiredAlternatives = contract.declaredRequiredResponseHeaders?.[initialStatus];
      const actualHasAzureAsync = Boolean(initial.response.headers["azure-asyncoperation"]);
      const actualHasLocation = Boolean(initial.response.headers.location);
      const actualHasOpLocation = Boolean(initial.response.headers["operation-location"]);

      // Respect optional polling headers & response alternatives (#4113):
      // only report missing headers when NO declared response alternative has its required polling headers satisfied.
      const missingRequiredHeader =
        requiredAlternatives && requiredAlternatives.length > 0
          ? !requiredAlternatives.some((reqSet) =>
              reqSet
                .filter(
                  (h) =>
                    h === "azure-asyncoperation" || h === "location" || h === "operation-location",
                )
                .every((h) => Boolean(initial.response.headers[h])),
            )
          : (declaredHeaders.includes("azure-asyncoperation") &&
              !actualHasAzureAsync &&
              !actualHasLocation) ||
            (declaredHeaders.includes("location") && !actualHasLocation && !actualHasAzureAsync);

      const allowsAzureAsync = declaredHeaders.includes("azure-asyncoperation");
      const unexpectedAzureAsync =
        declaredHeaders.length > 0 && !allowsAzureAsync && actualHasAzureAsync;

      if (
        (initial.response.status === 201 || initial.response.status === 202) &&
        observedLro.detected &&
        (missingRequiredHeader || unexpectedAzureAsync)
      ) {
        discrepancies.push({
          ruleId: DISCREPANCY_RULES.LRO_HEADER_DRIFT,
          severity: "warning",
          operationId: contract.operationId,
          sourceLocation: contract.sourceLocation,
          summary: `Declared LRO polling headers for HTTP ${initialStatus} on ${contract.operationId} do not match live wire headers.`,
          specExpectation: `Declared response headers on ${initialStatus}: [${declaredHeaders.join(", ")}]${requiredAlternatives ? ` (required alternatives: ${JSON.stringify(requiredAlternatives)})` : ""}.`,
          actualWireBehavior: `Live response provided: azure-asyncoperation=${actualHasAzureAsync}, location=${actualHasLocation}, operation-location=${actualHasOpLocation}.`,
          evidence: {
            declaredHeaders,
            requiredAlternatives,
            actualAsyncOperation: actualHasAzureAsync,
            actualLocation: actualHasLocation,
            actualOperationLocation: actualHasOpLocation,
          },
        });
      }
    }

    // 3. POST LRO final-state-via drift.
    if (contract.method === "POST" && contract.lroFinalStateVia && observedLro.detected) {
      const fsv = contract.lroFinalStateVia.toLowerCase();
      if (
        (fsv === "location" &&
          !initial.response.headers.location &&
          observedLro.finalResultSource === "status-monitor-body") ||
        (fsv === "azure-async-operation" &&
          !initial.response.headers["azure-asyncoperation"] &&
          observedLro.finalResultSource === "location-body")
      ) {
        discrepancies.push({
          ruleId: DISCREPANCY_RULES.LRO_FINAL_STATE_DRIFT,
          severity: "blocking",
          operationId: contract.operationId,
          summary: `POST LRO ${contract.operationId} declares final-state-via="${contract.lroFinalStateVia}", which disagrees with live final-result delivery (${observedLro.finalResultSource}).`,
          specExpectation: `x-ms-long-running-operation-options.final-state-via = "${contract.lroFinalStateVia}".`,
          actualWireBehavior: `Final result was delivered via "${observedLro.finalResultSource}" (azure-asyncoperation=${Boolean(initial.response.headers["azure-asyncoperation"])}, location=${Boolean(initial.response.headers.location)}).`,
          evidence: {
            declaredFinalStateVia: contract.lroFinalStateVia,
            observedFinalResultSource: observedLro.finalResultSource,
          },
        });
      }
    }
  }

  // 4. Undocumented HTTP status code on non-error responses.
  if (!expectError && !isErrorStatus && !contract.declaredStatusCodes.includes(initialStatus)) {
    discrepancies.push({
      ruleId: DISCREPANCY_RULES.STATUS_CODE_DRIFT,
      severity: "blocking",
      operationId: contract.operationId,
      summary: `Live service returned undocumented HTTP status ${initialStatus} for ${contract.operationId}.`,
      specExpectation: `Declared success status codes: [${contract.declaredStatusCodes.join(", ")}].`,
      actualWireBehavior: `Service returned HTTP ${initialStatus}.`,
      evidence: {
        declaredStatusCodes: contract.declaredStatusCodes,
        actualStatusCode: initial.response.status,
      },
    });
  }

  // 5. Spec-valid request rejected by live service (400 BadRequest with 0 TypeSpec request errors).
  const hardRequestErrors = requestSchemaErrors.filter((e) => e.severity === "error");
  if (!expectError && initial.response.status === 400 && hardRequestErrors.length === 0) {
    discrepancies.push({
      ruleId: DISCREPANCY_RULES.SCHEMA_REQUEST_REJECTED,
      severity: "warning",
      operationId: contract.operationId,
      sourceLocation: contract.sourceLocation,
      summary: `Request payload satisfied the TypeSpec request model (0 request schema errors), but live service rejected it with HTTP 400.`,
      specExpectation: `Payload conforming to ${contract.operationId} TypeSpec parameter/body models should be accepted or constraints should be modeled in TypeSpec.`,
      actualWireBehavior: `Service returned HTTP 400: ${JSON.stringify(initial.response.body ?? initial.response.rawTextSnippet ?? {}).slice(0, 300)}`,
      evidence: {
        status: 400,
        errorBody: initial.response.body,
      },
    });
  }

  // 6. Response schema drift reported by TypeSpec wire validator.
  if (!expectError && isInitial2xx && responseSchemaErrors.length > 0) {
    discrepancies.push({
      ruleId: DISCREPANCY_RULES.SCHEMA_RESPONSE_DRIFT,
      severity: "warning",
      operationId: contract.operationId,
      sourceLocation: contract.sourceLocation,
      summary: `TypeSpec wire validator found ${responseSchemaErrors.length} response schema discrepancy(ies) on ${contract.operationId}.`,
      specExpectation: `Live response body and headers must conform to the TypeSpec response model for HTTP ${initialStatus}.`,
      actualWireBehavior: responseSchemaErrors
        .slice(0, 5)
        .map((e) => `[${e.code}] ${e.message}`)
        .join("; "),
      evidence: {
        issues: responseSchemaErrors,
      },
    });
  }

  // 6b. Undeclared response body on a schema-less declared 2xx status code (e.g. 202 returning a resource JSON body when TypeSpec declares void body).
  if (
    !expectError &&
    isInitial2xx &&
    contract.declaredStatusCodes.includes(initialStatus) &&
    contract.declaredResponseHasSchema[initialStatus] === false &&
    initial.response.body !== undefined
  ) {
    discrepancies.push({
      ruleId: DISCREPANCY_RULES.SCHEMA_RESPONSE_DRIFT,
      severity: "warning",
      operationId: contract.operationId,
      sourceLocation: contract.sourceLocation,
      summary: `Live HTTP ${initialStatus} response on ${contract.operationId} returned a JSON body, but TypeSpec declares no response body for ${initialStatus}.`,
      specExpectation: `HTTP ${initialStatus} response has no body model in TypeSpec.`,
      actualWireBehavior: `Live service returned a JSON body with keys [${typeof initial.response.body === "object" && initial.response.body ? Object.keys(initial.response.body).join(", ") : typeof initial.response.body}].`,
      evidence: {
        statusCode: initial.response.status,
      },
    });
  }
  // 7. Error envelope drift on 4xx/5xx responses.
  if (isErrorStatus) {
    const body = initial.response.body;
    const errorObj =
      body && typeof body === "object" ? (body as Record<string, unknown>).error : undefined;
    const hasStandardArmError =
      Boolean(errorObj) &&
      typeof errorObj === "object" &&
      typeof (errorObj as Record<string, unknown>).code === "string" &&
      typeof (errorObj as Record<string, unknown>).message === "string";

    if (!contract.hasDefaultErrorResponse || !hasStandardArmError) {
      discrepancies.push({
        ruleId: DISCREPANCY_RULES.ERROR_ENVELOPE_DRIFT,
        severity: !hasStandardArmError ? "blocking" : "warning",
        operationId: contract.operationId,
        summary: !hasStandardArmError
          ? `Error response HTTP ${initialStatus} on ${contract.operationId} does not follow ARM OData v4 { error: { code, message } } contract.`
          : `Operation ${contract.operationId} omits a "default" error response in the spec, while service returned HTTP ${initialStatus}.`,
        specExpectation: `ARM operations must declare a default ErrorResponse and return { error: { code, message } } on non-2xx responses.`,
        actualWireBehavior: `HTTP ${initialStatus} body keys: [${body && typeof body === "object" ? Object.keys(body).join(", ") : "non-json"}].`,
        evidence: {
          status: initial.response.status,
          hasDefaultErrorResponse: contract.hasDefaultErrorResponse,
          hasStandardArmError,
        },
      });
    }
  }

  // 8. Pagination contract drift (`x-ms-pageable` vs actual response across initial & continuation pages).
  if (!expectError && isInitial2xx && contract.method === "GET") {
    const pageExchanges = [initial, ...exchanges.filter((ex) => ex.step === "next-page")];
    for (let pageIdx = 0; pageIdx < pageExchanges.length; pageIdx++) {
      const pageEx = pageExchanges[pageIdx];
      if (pageIdx > 0 && (pageEx.response.status < 200 || pageEx.response.status >= 300)) {
        discrepancies.push({
          ruleId: DISCREPANCY_RULES.STATUS_CODE_DRIFT,
          severity: "blocking",
          operationId: contract.operationId,
          sourceLocation: contract.sourceLocation,
          summary: `Continuation page ${pageIdx + 1} on ${contract.operationId} failed with HTTP ${pageEx.response.status}.`,
          specExpectation: `Every nextLink continuation page must return HTTP 200 matching the paged list schema.`,
          actualWireBehavior: `Page ${pageIdx + 1} (${pageEx.request.url}) returned HTTP ${pageEx.response.status}.`,
          evidence: {
            pageIndex: pageIdx + 1,
            status: pageEx.response.status,
            url: pageEx.request.url,
          },
        });
        continue;
      }

      const respBody = pageEx.response.body;
      if (contract.pageable) {
        const itemField = contract.pageable.itemName || "value";
        const items =
          respBody && typeof respBody === "object" && !Array.isArray(respBody)
            ? (respBody as Record<string, unknown>)[itemField]
            : undefined;
        if (!Array.isArray(items)) {
          discrepancies.push({
            ruleId: DISCREPANCY_RULES.PAGEABLE_CONTRACT_DRIFT,
            severity: "blocking",
            operationId: contract.operationId,
            sourceLocation: contract.sourceLocation,
            summary: `Operation ${contract.operationId} declares x-ms-pageable (itemName="${itemField}"), but page ${pageIdx + 1} did not contain an array at "${itemField}".`,
            specExpectation: `JSON object containing array property "${itemField}"${contract.pageable.nextLinkName ? ` and optional "${contract.pageable.nextLinkName}"` : ""}.`,
            actualWireBehavior: Array.isArray(respBody)
              ? `Page ${pageIdx + 1} returned a bare top-level JSON array instead of { ${itemField}: [...] }.`
              : `Page ${pageIdx + 1} response top-level keys: [${respBody && typeof respBody === "object" ? Object.keys(respBody).join(", ") : typeof respBody}].`,
            evidence: {
              pageIndex: pageIdx + 1,
              declaredPageable: contract.pageable,
            },
          });
          break;
        }
      } else if (
        pageIdx === 0 &&
        respBody &&
        typeof respBody === "object" &&
        !Array.isArray(respBody) &&
        Array.isArray((respBody as Record<string, unknown>).value) &&
        typeof (respBody as Record<string, unknown>).nextLink === "string"
      ) {
        discrepancies.push({
          ruleId: DISCREPANCY_RULES.PAGEABLE_CONTRACT_DRIFT,
          severity: "warning",
          operationId: contract.operationId,
          sourceLocation: contract.sourceLocation,
          summary: `Live response on ${contract.operationId} returned { value, nextLink } pagination, but spec omits x-ms-pageable.`,
          specExpectation: `Non-pageable GET operation.`,
          actualWireBehavior: `Response included "value" array and continuation "nextLink".`,
          evidence: {
            hasNextLink: true,
          },
        });
      }
    }
  }

  // 9. Round-trip mutability check (PUT body vs completed 2xx terminal/GET resource body).
  const putBodySource = contract.method === "PUT" ? initial.request.body : priorPutBody;
  const terminalBody = terminalExchange.response.body;
  const isTerminal2xx =
    terminalExchange.response.status >= 200 && terminalExchange.response.status < 300;
  const lroCompletedSuccessfully =
    !observedLro.detected || observedLro.completionStatus === "succeeded";
  const isMonitoredPutWithoutFinalResourceGet =
    contract.method === "PUT" &&
    observedLro.detected &&
    (observedLro.pollingHeaderUsed === "azure-asyncoperation" ||
      observedLro.pollingHeaderUsed === "operation-location") &&
    terminalExchange.step !== "final-get";
  const terminalProvState = extractProvisioningState(terminalBody);
  const isTerminalResourceReady =
    !isNonTerminalProvisioningState(terminalProvState) &&
    !isFailedOrCanceledState(terminalProvState);
  if (
    !expectError &&
    isInitial2xx &&
    isTerminal2xx &&
    lroCompletedSuccessfully &&
    !isMonitoredPutWithoutFinalResourceGet &&
    isTerminalResourceReady &&
    putBodySource &&
    typeof putBodySource === "object" &&
    !Array.isArray(putBodySource) &&
    terminalBody &&
    typeof terminalBody === "object" &&
    !Array.isArray(terminalBody) &&
    (contract.method === "PUT" || (contract.method === "GET" && priorPutBody !== undefined))
  ) {
    const secretSet = new Set(contract.secretProperties.map((s) => s.toLowerCase()));
    const droppedProperties: string[] = [];

    for (const propPath of contract.writableBodyProperties) {
      if (secretSet.has(propPath.toLowerCase())) {
        continue;
      }
      // Only check leaf scalar/array values that were explicitly sent in the PUT request.
      const sentVal = getNestedValue(putBodySource, propPath);
      if (
        sentVal === undefined ||
        sentVal === null ||
        (typeof sentVal === "object" && !Array.isArray(sentVal))
      ) {
        continue;
      }
      const receivedVal = getNestedValue(terminalBody, propPath);
      if (receivedVal === undefined) {
        droppedProperties.push(propPath);
      }
    }

    if (droppedProperties.length > 0) {
      discrepancies.push({
        ruleId: DISCREPANCY_RULES.ROUNDTRIP_MUTABILITY_DRIFT,
        severity: "warning",
        operationId: contract.operationId,
        summary: `Writable non-secret property(ies) [${droppedProperties.join(", ")}] sent in PUT were absent from the resource representation returned by the service.`,
        specExpectation: `Writable properties without x-ms-mutability: ["create", "update"]-only/secret semantics should round-trip in GET/PUT responses.`,
        actualWireBehavior: `Properties omitted in response: [${droppedProperties.join(", ")}].`,
        evidence: {
          droppedProperties,
        },
      });
    }
  }

  // 10. ARM terminal provisioningState check on resource PUT/GET.
  if (
    !expectError &&
    isInitial2xx &&
    (contract.phase === "create" || contract.phase === "read") &&
    contract.scope === "resourceGroup" &&
    terminalBody &&
    typeof terminalBody === "object"
  ) {
    const termState = extractProvisioningState(terminalBody);
    if (termState && isNonTerminalProvisioningState(termState) && !contract.isLroDeclared) {
      // Already flagged under LRO-UNDECLARED if detected on initial; guard if GET still shows non-standard terminal string.
    } else if (
      termState &&
      observedLro.pollCount > 0 &&
      !TERMINAL_PROVISIONING_STATES.has(termState.toLowerCase())
    ) {
      discrepancies.push({
        ruleId: DISCREPANCY_RULES.PROVISIONING_STATE_DRIFT,
        severity: "warning",
        operationId: contract.operationId,
        summary: `Resource provisioningState ended at "${termState}", outside required ARM terminal states (Succeeded, Failed, Canceled).`,
        specExpectation: `ARM RPC requires terminal provisioningState values Succeeded, Failed, or Canceled.`,
        actualWireBehavior: `Terminal response had properties.provisioningState = "${termState}".`,
        evidence: {
          terminalProvisioningState: termState,
        },
      });
    }
  }

  for (const d of discrepancies) {
    if (!d.sourceLocation && contract.sourceLocation) {
      d.sourceLocation = contract.sourceLocation;
    }
  }
  return discrepancies;
}
