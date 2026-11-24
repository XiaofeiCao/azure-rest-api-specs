import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { getUnionAsEnum } from "@azure-tools/typespec-azure-core";
import {
  isArrayModelType,
  isRecordModelType,
  isSecret,
  isVoidType,
  resolveEncodedName,
  walkPropertiesInherited,
  type Program,
  type Type,
} from "@typespec/compiler";
import {
  createMetadataInfo,
  getPatchOptions,
  resolveRequestVisibility,
  Visibility,
  type MetadataInfo,
  type Visibility as VisibilityType,
} from "@typespec/http";
import {
  findHeaderCaseInsensitive,
  safeDecodeUriSegment,
  stripConfiguredArmBasePath,
} from "./auth-and-http.ts";
import { GENERATED_EXAMPLES_DIRNAME, loadAllProbeTraces, loadLedger } from "./ledger-store.ts";
import type { BlackboxSummaryReport } from "./render-report.ts";
import { REPORT_PORTAL_APP_JS } from "./report-portal-app-template.ts";
import { sanitizePayload, type SanitizeContext } from "./sanitize-example.ts";
import { loadProjectedTypeSpecService } from "./typespec-loader.ts";
import type { CoverageLedger, OperationContract } from "./types.ts";

export const LOCAL_HTML_REPORT_DIRNAME = "report-html";

export interface ParameterCoverageItem {
  name: string;
  in: "path" | "query" | "header" | "body";
  required: boolean;
  type: string;
  secret: boolean;
  exercised: boolean;
  sampleValue?: string;
}

export interface ParameterCoverageStats {
  total: number;
  exercised: number;
  percent: number;
  requiredTotal: number;
  requiredExercised: number;
  requiredPercent: number;
  optionalTotal: number;
  optionalExercised: number;
  optionalPercent: number;
  byLocation: Record<"path" | "query" | "header" | "body", { total: number; exercised: number }>;
}

export interface PortalWireStepSummary {
  step: string;
  method: string;
  status: number;
  durationMs: number;
  sanitizedUrl: string;
}

export interface PortalOperationEntry {
  operationId: string;
  method: string;
  pathTemplate: string;
  phase: string;
  resourceType: string;
  scope: string;
  isLroDeclared: boolean;
  isPageable: boolean;
  status: string;
  attempts: number;
  lastHttpStatus?: number;
  observedLro?: {
    detected: boolean;
    pollCount: number;
    pollingHeaderUsed?: string;
    terminalProvisioningState?: string;
  };
  sourceLabel?: string;
  githubSourceUrl?: string;
  discrepancyCount: number;
  blockerReason?: string;
  parameterStats: ParameterCoverageStats;
  parameters: ParameterCoverageItem[];
  wireSteps: PortalWireStepSummary[];
  examples: Array<{
    name: string;
    content: unknown;
  }>;
}

export interface PortalDiscrepancyEntry {
  serviceId: string;
  providerNamespace: string;
  apiVersion: string;
  ruleId: string;
  severity: "blocking" | "warning" | "info";
  operationId: string;
  sourceLabel?: string;
  githubSourceUrl?: string;
  summary: string;
  specExpectation: string;
  actualWireBehavior: string;
  evidence: Record<string, unknown>;
}

export interface PortalServiceEntry {
  serviceId: string;
  serviceName: string;
  providerNamespace: string;
  apiVersion: string;
  availableApiVersions: string[];
  armBaseUrl: string;
  specRelativeDir: string;
  githubSpecUrl?: string;
  testedAt: string;
  region?: string;
  rgCleanupStatus?: string;
  apiCoverage: BlackboxSummaryReport["coverageSummary"];
  parameterCoverage: ParameterCoverageStats;
  discrepancySummary: BlackboxSummaryReport["discrepancySummary"];
  generatedExamplesCount: number;
  discrepancies: PortalDiscrepancyEntry[];
  operations: PortalOperationEntry[];
}

export interface PortalDataBundle {
  schemaVersion: "1.0";
  generatedAt: string;
  portfolioSummary: {
    totalServices: number;
    totalOperations: number;
    testedOperations: number;
    apiCoveragePercent: number;
    parameterCoverage: ParameterCoverageStats;
    totalDiscrepancies: number;
    blockingDiscrepancies: number;
    warningDiscrepancies: number;
    totalGeneratedExamples: number;
  };
  services: PortalServiceEntry[];
}

const SECRET_NAME_RE =
  /(password|secret|connectionstring|primarykey|secondarykey|accesskey|apikey|sastoken|sharedkey|clientsecret|privatekey|token)/i;

function pct(num: number, den: number): number {
  return den === 0 ? 100 : Number(((num / den) * 100).toFixed(1));
}

function summarizeParamStats(items: ParameterCoverageItem[]): ParameterCoverageStats {
  const byLocation: ParameterCoverageStats["byLocation"] = {
    path: { total: 0, exercised: 0 },
    query: { total: 0, exercised: 0 },
    header: { total: 0, exercised: 0 },
    body: { total: 0, exercised: 0 },
  };
  let requiredTotal = 0;
  let requiredExercised = 0;
  let optionalTotal = 0;
  let optionalExercised = 0;

  for (const item of items) {
    byLocation[item.in].total += 1;
    if (item.exercised) {
      byLocation[item.in].exercised += 1;
    }
    if (item.required) {
      requiredTotal += 1;
      if (item.exercised) requiredExercised += 1;
    } else {
      optionalTotal += 1;
      if (item.exercised) optionalExercised += 1;
    }
  }

  const total = items.length;
  const exercised = requiredExercised + optionalExercised;
  return {
    total,
    exercised,
    percent: pct(exercised, total),
    requiredTotal,
    requiredExercised,
    requiredPercent: pct(requiredExercised, requiredTotal),
    optionalTotal,
    optionalExercised,
    optionalPercent: pct(optionalExercised, optionalTotal),
    byLocation,
  };
}

function mergeParamStats(list: ParameterCoverageStats[]): ParameterCoverageStats {
  const byLocation: ParameterCoverageStats["byLocation"] = {
    path: { total: 0, exercised: 0 },
    query: { total: 0, exercised: 0 },
    header: { total: 0, exercised: 0 },
    body: { total: 0, exercised: 0 },
  };
  let requiredTotal = 0;
  let requiredExercised = 0;
  let optionalTotal = 0;
  let optionalExercised = 0;

  for (const s of list) {
    requiredTotal += s.requiredTotal;
    requiredExercised += s.requiredExercised;
    optionalTotal += s.optionalTotal;
    optionalExercised += s.optionalExercised;
    for (const loc of ["path", "query", "header", "body"] as const) {
      byLocation[loc].total += s.byLocation[loc].total;
      byLocation[loc].exercised += s.byLocation[loc].exercised;
    }
  }
  const total = requiredTotal + optionalTotal;
  const exercised = requiredExercised + optionalExercised;
  return {
    total,
    exercised,
    percent: pct(exercised, total),
    requiredTotal,
    requiredExercised,
    requiredPercent: pct(requiredExercised, requiredTotal),
    optionalTotal,
    optionalExercised,
    optionalPercent: pct(optionalExercised, optionalTotal),
    byLocation,
  };
}

function formatTypeSpecTypeLabel(program: Program, type: Type): string {
  if (type.kind === "Scalar") {
    return type.name;
  }
  if (type.kind === "Enum") {
    return type.name || "enum";
  }
  if (type.kind === "Union") {
    const [unionEnum] = getUnionAsEnum(type);
    if (unionEnum) {
      return type.name || "union";
    }
    return type.name || "union";
  }
  if (type.kind === "Model") {
    if (isArrayModelType(program, type)) {
      return `${formatTypeSpecTypeLabel(program, type.indexer.value)}[]`;
    }
    if (isRecordModelType(program, type)) {
      return `Record<${formatTypeSpecTypeLabel(program, type.indexer.value)}>`;
    }
    return type.name || "object";
  }
  return type.kind.toLowerCase();
}

interface BodyLeafSpec {
  dotPath: string;
  required: boolean;
  type: string;
  secret: boolean;
}

function upsertBodyLeaf(map: Map<string, BodyLeafSpec>, next: BodyLeafSpec): void {
  const existing = map.get(next.dotPath);
  if (!existing) {
    map.set(next.dotPath, next);
    return;
  }
  map.set(next.dotPath, {
    dotPath: next.dotPath,
    required: existing.required && next.required,
    type: existing.type,
    secret: existing.secret || next.secret,
  });
}

function collectRequestBodyLeafSpecs(
  program: Program,
  metadataInfo: MetadataInfo,
  reqVisibility: VisibilityType,
  isPatchImplicitOptional: boolean,
  type: Type | undefined,
  prefix = "",
  ancestorsRequired = true,
  inheritedSecret = false,
  depth = 0,
  visited = new Set<Type>(),
  out = new Map<string, BodyLeafSpec>(),
): BodyLeafSpec[] {
  if (!type || depth > 6 || visited.has(type)) {
    return [...out.values()];
  }

  const branchVisited = new Set(visited);
  branchVisited.add(type);

  if (type.kind === "Union") {
    for (const variant of type.variants.values()) {
      collectRequestBodyLeafSpecs(
        program,
        metadataInfo,
        reqVisibility,
        isPatchImplicitOptional,
        variant.type,
        prefix,
        false,
        inheritedSecret || isSecret(program, variant.type),
        depth,
        branchVisited,
        out,
      );
    }
    return [...out.values()];
  }

  if (type.kind === "Model") {
    const modelSecret = inheritedSecret || isSecret(program, type);
    if (isArrayModelType(program, type)) {
      const elemType = type.indexer.value;
      if (elemType.kind === "Model" && !isRecordModelType(program, elemType)) {
        collectRequestBodyLeafSpecs(
          program,
          metadataInfo,
          reqVisibility | Visibility.Item,
          false,
          elemType,
          `${prefix}[]`,
          false,
          modelSecret || isSecret(program, elemType),
          depth + 1,
          branchVisited,
          out,
        );
      }
      return [...out.values()];
    }

    if (isRecordModelType(program, type)) {
      return [...out.values()];
    }

    for (const prop of walkPropertiesInherited(type)) {
      if (!metadataInfo.isPayloadProperty(prop, reqVisibility)) {
        continue;
      }
      const wireName = resolveEncodedName(program, prop, "application/json");
      const propPath = prefix ? `${prefix}.${wireName}` : wireName;
      const isOptional =
        (depth === 0 && isPatchImplicitOptional) ||
        prop.optional ||
        metadataInfo.isOptional(prop, reqVisibility);
      const isReq = ancestorsRequired && !isOptional;
      const secret =
        modelSecret ||
        isSecret(program, prop) ||
        isSecret(program, prop.type) ||
        SECRET_NAME_RE.test(wireName);
      const propType = prop.type;

      let hasNestedModelChildren = false;
      if (
        propType.kind === "Model" &&
        !isArrayModelType(program, propType) &&
        !isRecordModelType(program, propType)
      ) {
        for (const childProp of walkPropertiesInherited(propType)) {
          if (metadataInfo.isPayloadProperty(childProp, reqVisibility)) {
            hasNestedModelChildren = true;
            break;
          }
        }
        if (propType.derivedModels.length > 0) {
          hasNestedModelChildren = true;
        }
      }

      if (hasNestedModelChildren) {
        collectRequestBodyLeafSpecs(
          program,
          metadataInfo,
          reqVisibility,
          false,
          propType,
          propPath,
          isReq,
          secret,
          depth + 1,
          branchVisited,
          out,
        );
      } else if (propType.kind === "Model" && isArrayModelType(program, propType)) {
        upsertBodyLeaf(out, {
          dotPath: propPath,
          required: isReq,
          type: formatTypeSpecTypeLabel(program, propType),
          secret,
        });
        collectRequestBodyLeafSpecs(
          program,
          metadataInfo,
          reqVisibility | Visibility.Item,
          false,
          propType,
          propPath,
          false,
          secret,
          depth + 1,
          branchVisited,
          out,
        );
      } else if (propType.kind === "Union") {
        const [unionEnum] = getUnionAsEnum(propType);
        if (unionEnum) {
          upsertBodyLeaf(out, {
            dotPath: propPath,
            required: isReq,
            type: formatTypeSpecTypeLabel(program, propType),
            secret,
          });
        } else {
          collectRequestBodyLeafSpecs(
            program,
            metadataInfo,
            reqVisibility,
            false,
            propType,
            propPath,
            isReq,
            secret,
            depth + 1,
            branchVisited,
            out,
          );
        }
      } else {
        upsertBodyLeaf(out, {
          dotPath: propPath,
          required: isReq,
          type: formatTypeSpecTypeLabel(program, propType),
          secret,
        });
      }
    }

    for (const derived of type.derivedModels) {
      collectRequestBodyLeafSpecs(
        program,
        metadataInfo,
        reqVisibility,
        false,
        derived,
        prefix,
        false,
        modelSecret || isSecret(program, derived),
        depth,
        branchVisited,
        out,
      );
    }
  }
  return [...out.values()];
}

function lookupBodyDotPathValues(root: unknown, dotPath: string): unknown[] {
  const segments = dotPath.split(".");
  let frontier: unknown[] = [root];

  for (const seg of segments) {
    const nextFrontier: unknown[] = [];
    const isArrayHop = seg.endsWith("[]");
    const propKey = isArrayHop ? seg.slice(0, -2) : seg;

    for (const current of frontier) {
      if (!current || typeof current !== "object" || Array.isArray(current)) {
        continue;
      }
      const val = (current as Record<string, unknown>)[propKey];
      if (val === undefined) {
        continue;
      }
      if (isArrayHop) {
        if (Array.isArray(val)) {
          for (const item of val) {
            if (item !== undefined) nextFrontier.push(item);
          }
        }
      } else {
        nextFrontier.push(val);
      }
    }
    frontier = nextFrontier;
    if (frontier.length === 0) {
      break;
    }
  }
  return frontier;
}

function extractPathParamsFromUrl(
  pathTemplate: string,
  actualUrl: string,
  armBaseUrl?: string,
): Record<string, string> {
  const cleanTemplate = pathTemplate.split("?")[0].replace(/^\/+|\/+$/g, "");
  const actualPathname = stripConfiguredArmBasePath(actualUrl, armBaseUrl).replace(
    /^\/+|\/+$/g,
    "",
  );
  const tSegs = cleanTemplate.split("/");
  const aSegs = actualPathname.split("/");
  const out: Record<string, string> = {};

  if (tSegs.length === aSegs.length) {
    for (let i = 0; i < tSegs.length; i++) {
      const m = /^\{([^}]+)\}$/.exec(tSegs[i]);
      if (m && aSegs[i]) {
        out[m[1].toLowerCase()] = safeDecodeUriSegment(aSegs[i]);
      }
    }
    return out;
  }

  const names: string[] = [];
  const regexStr = tSegs
    .map((seg) => {
      const m = /^\{([^}]+)\}$/.exec(seg);
      if (m) {
        names.push(m[1].toLowerCase());
        return "(.+?)";
      }
      return seg.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    })
    .join("\\/");
  const match = new RegExp(`^${regexStr}$`, "i").exec(actualPathname);
  if (match) {
    names.forEach((n, idx) => {
      out[n] = safeDecodeUriSegment(match[idx + 1]);
    });
  }
  return out;
}

function normalizeSourceInfo(
  rawFile: string | undefined,
  line: number | undefined,
): { sourceLabel?: string; githubSourceUrl?: string } {
  if (!rawFile || !line) {
    return {};
  }
  const norm = rawFile.replace(/\\/g, "/");
  const specIdx = norm.indexOf("/specification/");
  if (specIdx >= 0) {
    const relFromRepo = norm.slice(specIdx + 1);
    const shortName = path.posix.basename(relFromRepo);
    return {
      sourceLabel: `${shortName}:${line}`,
      githubSourceUrl: `https://github.com/Azure/azure-rest-api-specs/blob/main/${relFromRepo}#L${line}`,
    };
  }
  const nmIdx = norm.lastIndexOf("/node_modules/@");
  if (nmIdx >= 0) {
    const pkgRel = norm.slice(nmIdx + "/node_modules/".length);
    return {
      sourceLabel: `${pkgRel}:${line}`,
    };
  }
  return {
    sourceLabel: `${path.posix.basename(norm)}:${line}`,
  };
}

function buildOperationSanitizeContext(
  ledger: CoverageLedger,
  contract?: OperationContract,
): SanitizeContext {
  return {
    subscriptionId: ledger.subscriptionId,
    disposableRgName: ledger.disposableResourceGroup?.name,
    armBaseUrl: ledger.armBaseUrl,
    allowedArmOrigins: ledger.allowedArmOrigins,
    extraSecretPropertyPaths: contract?.secretProperties,
    secretQueryParamNames: contract?.parameters
      .filter((p) => p.in === "query" && p.secretCandidate)
      .map((p) => p.name),
    secretPathTemplate: contract?.pathTemplate,
    secretPathSlotNames: contract?.parameters
      .filter((p) => p.in === "path" && p.secretCandidate)
      .map((p) => p.name),
    secretCycleRules: contract?.secretCycleRules,
    secretConstraints: contract?.secretConstraints,
  };
}

function formatPreSanitizedPreview(val: unknown, isSecretField: boolean): string {
  if (isSecretField) {
    return "<redacted>";
  }
  const rawStr = typeof val === "string" ? val : JSON.stringify(val);
  if (!rawStr) {
    return "";
  }
  return rawStr.length > 72 ? `${rawStr.slice(0, 69)}...` : rawStr;
}

function serializeSafeJsonForInlineScript(data: unknown): string {
  return JSON.stringify(data, null, 2)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

async function aggregateServiceRunForHtml(
  runDir: string,
  precomputedReport?: BlackboxSummaryReport,
): Promise<PortalServiceEntry> {
  const ledger = loadLedger(runDir);
  const report: BlackboxSummaryReport =
    precomputedReport ??
    (JSON.parse(
      fs.readFileSync(path.join(runDir, "blackbox-report.json"), "utf8"),
    ) as BlackboxSummaryReport);

  const traces = loadAllProbeTraces(runDir);
  const examplesDir = path.join(runDir, GENERATED_EXAMPLES_DIRNAME, ledger.apiVersion);
  const exampleFiles = fs.existsSync(examplesDir)
    ? fs
        .readdirSync(examplesDir)
        .filter((f) => f.endsWith(".json"))
        .sort()
    : [];

  const examplesByOp = new Map<string, Array<{ name: string; content: unknown }>>();
  for (const file of exampleFiles) {
    const parsed = JSON.parse(fs.readFileSync(path.join(examplesDir, file), "utf8")) as {
      operationId?: string;
    };
    const opId = parsed.operationId ?? file.replace(/\.json$/, "");
    const contract = ledger.operations[opId];
    const opCtx = buildOperationSanitizeContext(ledger, contract);
    const list = examplesByOp.get(opId) ?? [];
    list.push({
      name: file.replace(/\.json$/, ""),
      content: sanitizePayload(parsed, opCtx),
    });
    examplesByOp.set(opId, list);
  }

  let tspService: Awaited<ReturnType<typeof loadProjectedTypeSpecService>> | undefined;
  let metadataInfo: MetadataInfo | undefined;
  try {
    tspService = await loadProjectedTypeSpecService(ledger.typespecProjectDir, ledger.apiVersion);
    metadataInfo = createMetadataInfo(tspService.program);
  } catch {
    // Graceful fallback when TypeSpec source tree is absent (e.g., relocated scratch directory).
  }

  const normProjectDir = ledger.typespecProjectDir.replace(/\\/g, "/");
  const specIdx = normProjectDir.indexOf("/specification/");
  const specRelativeDir =
    specIdx >= 0 ? normProjectDir.slice(specIdx + 1) : path.basename(normProjectDir);
  const githubSpecUrl =
    specIdx >= 0
      ? `https://github.com/Azure/azure-rest-api-specs/tree/main/${specRelativeDir}`
      : undefined;
  const runDiscriminator =
    ledger.runId ??
    crypto
      .createHash("sha256")
      .update(path.resolve(runDir).toLowerCase())
      .digest("hex")
      .slice(0, 8);
  const serviceId = `${ledger.providerNamespace.toLowerCase()}::${ledger.apiVersion}::${runDiscriminator}`;

  const operations: PortalOperationEntry[] = [];
  for (const opId of ledger.executionOrder) {
    const contract = ledger.operations[opId];
    const cov = ledger.coverage[opId];
    const opCtx = buildOperationSanitizeContext(ledger, contract);
    const opTraces = traces.filter((t) => t.operationId === opId);
    const positiveOrAttemptedTraces = opTraces.filter((t) => !t.expectError);
    const tracesForParamCheck =
      positiveOrAttemptedTraces.length > 0 ? positiveOrAttemptedTraces : opTraces;

    const paramItems: ParameterCoverageItem[] = [];
    const secretPathsLower = new Set(contract.secretProperties.map((s) => s.toLowerCase()));

    // 1. Path / Query / Header parameters
    for (const p of contract.parameters) {
      if (p.in === "body") {
        continue;
      }
      if (p.in === "header" && p.name.toLowerCase() === "content-type") {
        continue;
      }
      const isParamSecret =
        Boolean(p.secretCandidate) || secretPathsLower.has(p.name.toLowerCase());

      let exercised = false;
      let sampleValue: string | undefined;

      for (const tr of tracesForParamCheck) {
        for (const ex of tr.exchanges) {
          if (ex.step !== "initial" && ex.step !== "next-page") {
            continue;
          }
          if (p.in === "path" && ex.step === "initial") {
            const pathVals = extractPathParamsFromUrl(
              contract.pathTemplate,
              ex.request.url,
              ledger.armBaseUrl,
            );
            const matched = pathVals[p.name.toLowerCase()];
            if (matched !== undefined && matched.length > 0) {
              exercised = true;
              const cleanVal = sanitizePayload(matched, opCtx, p.name);
              sampleValue = formatPreSanitizedPreview(cleanVal, isParamSecret);
              break;
            }
          } else if (p.in === "query") {
            const urlObj = new URL(ex.request.url);
            const qVal = urlObj.searchParams.get(p.name);
            if (qVal !== null) {
              exercised = true;
              const cleanVal = sanitizePayload(qVal, opCtx, p.name);
              sampleValue = formatPreSanitizedPreview(cleanVal, isParamSecret);
              break;
            }
          } else if (p.in === "header" && ex.step === "initial") {
            const hVal = findHeaderCaseInsensitive(ex.request.headers, p.name);
            if (hVal !== undefined) {
              exercised = true;
              const cleanVal = sanitizePayload(hVal, opCtx, p.name);
              sampleValue = formatPreSanitizedPreview(cleanVal, isParamSecret);
              break;
            }
          }
        }
        if (exercised) break;
      }

      paramItems.push({
        name: p.name,
        in: p.in,
        required: p.required,
        type: p.type ?? "string",
        secret: isParamSecret,
        exercised,
        ...(sampleValue !== undefined ? { sampleValue } : {}),
      });
    }

    // 2. Request Body leaf & nested properties from TypeSpec AST (with ledger fallback)
    const httpOp = tspService?.operationsById.get(opId);
    const reqBody = httpOp?.parameters.body;
    let bodyLeaves: BodyLeafSpec[] = [];
    if (tspService && metadataInfo && httpOp && reqBody && !isVoidType(reqBody.type)) {
      const reqVisibility = resolveRequestVisibility(
        tspService.program,
        httpOp.operation,
        httpOp.verb,
      );
      const patchOpts =
        httpOp.verb === "patch" ? getPatchOptions(tspService.program, httpOp.operation) : undefined;
      const isPatchImplicitOptional =
        httpOp.verb === "patch" && patchOpts?.implicitOptionality !== false;
      const bodyRequired = reqBody.property ? !reqBody.property.optional : true;
      const wholeBodySecret =
        (reqBody.property ? isSecret(tspService.program, reqBody.property) : false) ||
        isSecret(tspService.program, reqBody.type);

      bodyLeaves = collectRequestBodyLeafSpecs(
        tspService.program,
        metadataInfo,
        reqVisibility,
        isPatchImplicitOptional,
        reqBody.type,
        "",
        bodyRequired,
        wholeBodySecret,
      );
    } else if (contract.writableBodyProperties.length > 0) {
      bodyLeaves = contract.writableBodyProperties.map((propPath) => ({
        dotPath: propPath,
        required: false,
        type: "unknown",
        secret: secretPathsLower.has(propPath.toLowerCase()),
      }));
    }

    if (bodyLeaves.length > 0) {
      // Pre-sanitize whole request bodies once per trace so recursive/container/@pattern secret rules apply cleanly!
      const sanitizedTraceBodies = tracesForParamCheck.map((tr) =>
        tr.exchanges[0]?.request.body !== undefined
          ? sanitizePayload(tr.exchanges[0].request.body, opCtx)
          : undefined,
      );

      for (const leaf of bodyLeaves) {
        const isLeafSecret = leaf.secret || secretPathsLower.has(leaf.dotPath.toLowerCase());
        let exercised = false;
        let sampleValue: string | undefined;

        for (let tIdx = 0; tIdx < tracesForParamCheck.length; tIdx++) {
          const rawBody = tracesForParamCheck[tIdx].exchanges[0]?.request.body;
          const sanitizedBody = sanitizedTraceBodies[tIdx];
          if (rawBody !== undefined) {
            const rawMatches = lookupBodyDotPathValues(rawBody, leaf.dotPath);
            if (rawMatches.length > 0 && rawMatches[0] !== undefined) {
              exercised = true;
              const sanitizedMatches = lookupBodyDotPathValues(sanitizedBody, leaf.dotPath);
              sampleValue = formatPreSanitizedPreview(sanitizedMatches[0], isLeafSecret);
              break;
            }
          }
        }

        paramItems.push({
          name: leaf.dotPath,
          in: "body",
          required: leaf.required,
          type: leaf.type,
          secret: isLeafSecret,
          exercised,
          ...(sampleValue !== undefined ? { sampleValue } : {}),
        });
      }
    }

    const latestPositiveTrace =
      positiveOrAttemptedTraces[positiveOrAttemptedTraces.length - 1] ??
      opTraces[opTraces.length - 1];
    const sourceInfo = normalizeSourceInfo(
      contract.sourceLocation?.file,
      contract.sourceLocation?.line,
    );

    const wireSteps: PortalWireStepSummary[] = (latestPositiveTrace?.exchanges ?? []).map((ex) => {
      const sanitizedFullUrl = String(sanitizePayload(ex.request.url, opCtx));
      let displayUrl = sanitizedFullUrl;
      try {
        const u = new URL(sanitizedFullUrl);
        displayUrl = `${u.pathname}${u.search}`.replace(/%3Credacted%3E/gi, "<redacted>");
      } catch {
        // Keep sanitized URL string if non-standard.
      }
      return {
        step: ex.step,
        method: ex.request.method,
        status: ex.response.status,
        durationMs: ex.durationMs,
        sanitizedUrl: displayUrl,
      };
    });

    operations.push({
      operationId: opId,
      method: contract.method,
      pathTemplate: contract.pathTemplate,
      phase: contract.phase,
      resourceType: contract.resourceType,
      scope: contract.scope,
      isLroDeclared: contract.isLroDeclared,
      isPageable: Boolean(contract.pageable),
      status: cov.status,
      attempts: cov.attempts,
      lastHttpStatus: cov.lastHttpStatus,
      observedLro: latestPositiveTrace
        ? {
            detected: latestPositiveTrace.observedLro.detected,
            pollCount: latestPositiveTrace.observedLro.pollCount,
            pollingHeaderUsed: latestPositiveTrace.observedLro.pollingHeaderUsed,
            terminalProvisioningState: latestPositiveTrace.observedLro.terminalProvisioningState,
          }
        : undefined,
      sourceLabel: sourceInfo.sourceLabel,
      githubSourceUrl: sourceInfo.githubSourceUrl,
      discrepancyCount: cov.discrepancyCount,
      blockerReason: cov.blockerReason
        ? String(sanitizePayload(cov.blockerReason, opCtx))
        : undefined,
      parameterStats: summarizeParamStats(paramItems),
      parameters: paramItems,
      wireSteps,
      examples: examplesByOp.get(opId) ?? [],
    });
  }

  const discrepancies: PortalDiscrepancyEntry[] = report.discrepancies.map((d) => {
    const contract = ledger.operations[d.operationId];
    const opCtx = buildOperationSanitizeContext(ledger, contract);
    const loc = d.sourceLocation ?? contract?.sourceLocation;
    const sourceInfo = normalizeSourceInfo(loc?.file, loc?.line);
    return {
      serviceId,
      providerNamespace: ledger.providerNamespace,
      apiVersion: ledger.apiVersion,
      ruleId: d.ruleId,
      severity: d.severity,
      operationId: d.operationId,
      sourceLabel: sourceInfo.sourceLabel,
      githubSourceUrl: sourceInfo.githubSourceUrl,
      summary: String(sanitizePayload(d.summary, opCtx)),
      specExpectation: String(sanitizePayload(d.specExpectation, opCtx)),
      actualWireBehavior: String(sanitizePayload(d.actualWireBehavior, opCtx)),
      evidence: sanitizePayload(d.evidence, opCtx) as Record<string, unknown>,
    };
  });

  const serviceParamStats = mergeParamStats(operations.map((o) => o.parameterStats));

  return {
    serviceId,
    serviceName: ledger.serviceName,
    providerNamespace: ledger.providerNamespace,
    apiVersion: ledger.apiVersion,
    availableApiVersions: ledger.availableApiVersions,
    armBaseUrl: ledger.armBaseUrl,
    specRelativeDir,
    ...(githubSpecUrl ? { githubSpecUrl } : {}),
    testedAt: report.generatedAt,
    region: ledger.disposableResourceGroup?.location ?? ledger.location,
    rgCleanupStatus: ledger.disposableResourceGroup?.cleanupStatus ?? "not_created",
    apiCoverage: report.coverageSummary,
    parameterCoverage: serviceParamStats,
    discrepancySummary: report.discrepancySummary,
    generatedExamplesCount: exampleFiles.length,
    discrepancies,
    operations,
  };
}

export async function renderLocalHtmlReportBundle(options: {
  workDir: string;
  precomputedPrimaryReport?: BlackboxSummaryReport;
  extraWorkDirs?: string[];
  outputDir?: string;
}): Promise<{
  htmlDir: string;
  htmlIndexPath: string;
  dataJsonPath: string;
  dataJsPath: string;
  bundle: PortalDataBundle;
}> {
  const htmlDir = options.outputDir ?? path.join(options.workDir, LOCAL_HTML_REPORT_DIRNAME);
  const assetsOutDir = path.join(htmlDir, "assets");
  fs.mkdirSync(assetsOutDir, { recursive: true });

  const staticAssetsRoot = path.resolve(import.meta.dirname, "../assets/report-portal");
  fs.copyFileSync(path.join(staticAssetsRoot, "index.html"), path.join(htmlDir, "index.html"));
  fs.copyFileSync(path.join(staticAssetsRoot, "styles.css"), path.join(assetsOutDir, "styles.css"));
  fs.writeFileSync(path.join(assetsOutDir, "app.js"), REPORT_PORTAL_APP_JS, "utf8");

  const services: PortalServiceEntry[] = [
    await aggregateServiceRunForHtml(options.workDir, options.precomputedPrimaryReport),
  ];
  const seenDirs = new Set<string>([path.resolve(options.workDir).toLowerCase()]);
  for (const extra of options.extraWorkDirs ?? []) {
    const resolved = path.resolve(extra).toLowerCase();
    if (seenDirs.has(resolved)) {
      continue;
    }
    seenDirs.add(resolved);
    services.push(await aggregateServiceRunForHtml(extra));
  }
  services.sort((a, b) => a.providerNamespace.localeCompare(b.providerNamespace));

  const totalOperations = services.reduce((acc, s) => acc + s.apiCoverage.totalOperations, 0);
  const testedOperations = services.reduce((acc, s) => acc + s.apiCoverage.testedOperations, 0);
  const totalDiscrepancies = services.reduce((acc, s) => acc + s.discrepancySummary.total, 0);
  const blockingDiscrepancies = services.reduce((acc, s) => acc + s.discrepancySummary.blocking, 0);
  const warningDiscrepancies = services.reduce((acc, s) => acc + s.discrepancySummary.warning, 0);
  const totalGeneratedExamples = services.reduce((acc, s) => acc + s.generatedExamplesCount, 0);
  const portfolioParamCoverage = mergeParamStats(services.map((s) => s.parameterCoverage));

  const bundle: PortalDataBundle = {
    schemaVersion: "1.0",
    generatedAt: new Date().toISOString(),
    portfolioSummary: {
      totalServices: services.length,
      totalOperations,
      testedOperations,
      apiCoveragePercent: pct(testedOperations, totalOperations),
      parameterCoverage: portfolioParamCoverage,
      totalDiscrepancies,
      blockingDiscrepancies,
      warningDiscrepancies,
      totalGeneratedExamples,
    },
    services,
  };

  const dataJsonPath = path.join(assetsOutDir, "portal-data.json");
  const dataJsPath = path.join(assetsOutDir, "portal-data.js");
  fs.writeFileSync(dataJsonPath, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  fs.writeFileSync(
    dataJsPath,
    `window.__ARM_BLACKBOX_PORTAL_DATA__ = ${serializeSafeJsonForInlineScript(bundle)};\n`,
    "utf8",
  );

  return {
    htmlDir,
    htmlIndexPath: path.join(htmlDir, "index.html"),
    dataJsonPath,
    dataJsPath,
    bundle,
  };
}
