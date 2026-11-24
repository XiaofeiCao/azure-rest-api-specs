import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  getArmResourceIdentifierConfig,
  getLroMetadata,
  getUnionAsEnum,
} from "@azure-tools/typespec-azure-core";
import {
  getDoc,
  getFormat,
  getMaxLength,
  getMinLength,
  getPagingOperation,
  getPattern,
  isArrayModelType,
  isErrorModel,
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
  resolveRequestVisibility,
  Visibility,
  type HttpOperation,
  type MetadataInfo,
} from "@typespec/http";
import { getExtensions, isReadonlyProperty } from "@typespec/openapi";
import { assertTrustedArmOrigin, getArmBearerToken } from "./auth-and-http.ts";
import {
  GENERATED_EXAMPLES_DIRNAME,
  getLedgerPath,
  loadLedger,
  saveLedger,
  TRACES_DIRNAME,
} from "./ledger-store.ts";
import {
  extractOperationSourceLocation,
  loadProjectedTypeSpecService,
  resolveBodyParameterName,
  resolveCanonicalOperationId,
} from "./typespec-loader.ts";
import type {
  ArmOperationScope,
  CoverageLedger,
  ExternalDependencyHint,
  HttpMethod,
  LifecyclePhase,
  OperationContract,
  OperationCoverageEntry,
  OperationParameterSpec,
  PageableContract,
  ProviderLiveMetadata,
} from "./types.ts";

const SECRET_PROPERTY_NAME_RE =
  /(password|secret|connectionstring|primarykey|secondarykey|accesskey|apikey|sastoken|sharedkey|clientsecret|privatekey|token)/i;

export interface DiscoverInventoryOptions {
  specPath: string;
  apiVersion?: string;
  workDir: string;
  armBaseUrl?: string;
  subscriptionId?: string;
  location?: string;
  checkLiveProvider?: boolean;
  reset?: boolean;
  bearerToken?: string;
}

function inferScope(pathTemplate: string): ArmOperationScope {
  const cleanPath = pathTemplate.split("?")[0];
  const providerMatches = [...cleanPath.matchAll(/\/providers\/([^/]+)/gi)];
  if (providerMatches.length >= 2) {
    return "extension";
  }
  if (/\/resourcegroups\/\{[^}]+\}/i.test(cleanPath)) {
    return "resourceGroup";
  }
  if (/^\/subscriptions\/\{[^}]+\}/i.test(cleanPath)) {
    return "subscription";
  }
  return "tenant";
}

function extractProviderAndResource(
  pathTemplate: string,
  method: HttpMethod,
): {
  providerNamespace: string;
  resourceType: string;
  depth: number;
  isActionSegment: boolean;
  lastStaticSegment: string;
} {
  const cleanPath = pathTemplate.split("?")[0].replace(/\/+$/, "");
  const providerIdx = cleanPath.toLowerCase().lastIndexOf("/providers/");
  if (providerIdx === -1) {
    return {
      providerNamespace: "Microsoft.Resources",
      resourceType: "Microsoft.Resources/subscriptions",
      depth: 0,
      isActionSegment: false,
      lastStaticSegment: "",
    };
  }

  const afterProviders = cleanPath.slice(providerIdx + "/providers/".length);
  const segments = afterProviders.split("/").filter(Boolean);
  const providerNamespace = segments[0] ?? "Unknown.Provider";
  const rest = segments.slice(1);

  // Filter out "/locations/{location}" prefix segments for location-based resources/deleted stores.
  const normalizedRest: string[] = [];
  for (let i = 0; i < rest.length; i++) {
    if (
      rest[i].toLowerCase() === "locations" &&
      i + 1 < rest.length &&
      rest[i + 1].startsWith("{")
    ) {
      i++;
      continue;
    }
    normalizedRest.push(rest[i]);
  }

  const typeSegments: string[] = [];
  let idx = 0;
  while (idx < normalizedRest.length) {
    const seg = normalizedRest[idx];
    if (!seg.startsWith("{")) {
      typeSegments.push(seg);
      if (idx + 1 < normalizedRest.length && normalizedRest[idx + 1].startsWith("{")) {
        idx += 2;
        continue;
      }
      // Singleton literal resource names (e.g., ".../identities/default") follow a static collection segment.
      if (
        idx + 1 < normalizedRest.length &&
        /^(default|current|latest)$/i.test(normalizedRest[idx + 1])
      ) {
        idx += 2;
        continue;
      }
    }
    idx++;
  }

  const endsWithParam =
    normalizedRest.length > 0 && normalizedRest[normalizedRest.length - 1].startsWith("{");
  const lastSegment = normalizedRest[normalizedRest.length - 1] ?? "";
  // Only POST routes ending in a static verb segment after a resource path are ARM actions;
  // GET/PUT/PATCH/DELETE ending in a static segment are child collections or singleton resources!
  const isActionSegment = method === "POST" && !endsWithParam && normalizedRest.length >= 2;

  const resourceTypeSegments =
    isActionSegment && typeSegments.length > 1 ? typeSegments.slice(0, -1) : typeSegments;
  const resourceType =
    resourceTypeSegments.length > 0
      ? `${providerNamespace}/${resourceTypeSegments.join("/")}`
      : providerNamespace;

  return {
    providerNamespace,
    resourceType,
    depth: resourceTypeSegments.length,
    isActionSegment,
    lastStaticSegment: endsWithParam ? "" : lastSegment,
  };
}

function classifyPhase(
  method: HttpMethod,
  pathTemplate: string,
  operationId: string,
  pageable: PageableContract | undefined,
): LifecyclePhase {
  const lowerPath = pathTemplate.toLowerCase();
  const lowerOp = operationId.toLowerCase();

  if (
    lowerPath.endsWith("/operations") ||
    lowerPath.endsWith("/checknameavailability") ||
    lowerOp.includes("checknameavailability") ||
    lowerOp.startsWith("operations_") ||
    lowerOp.includes("listskus") ||
    lowerOp.includes("usages")
  ) {
    return "preflight-discovery";
  }

  if (lowerPath.includes("/deleted") || lowerOp.includes("deleted")) {
    return "deleted-resource";
  }

  const cleanPath = pathTemplate.split("?")[0].replace(/\/+$/, "");
  const endsWithParam = cleanPath.endsWith("}");

  if (method === "PUT") {
    return "create";
  }
  if (method === "PATCH") {
    return "update";
  }
  if (method === "DELETE") {
    return "delete";
  }
  if (method === "POST") {
    return "action";
  }
  if (method === "GET") {
    if (pageable || !endsWithParam || lowerOp.includes("_list")) {
      return "list";
    }
    return "read";
  }
  return "read";
}

function describeTypeSpecType(type: Type): {
  typeName?: string;
  format?: string;
  enumValues?: string[];
  armAllowedType?: string;
} {
  if (type.kind === "Scalar") {
    return { typeName: type.name };
  }
  if (type.kind === "Enum") {
    return {
      typeName: "string",
      enumValues: [...type.members.values()].map((m) => String(m.value ?? m.name)),
    };
  }
  if (type.kind === "Union") {
    const [unionEnum] = getUnionAsEnum(type);
    if (unionEnum) {
      return {
        typeName: "string",
        enumValues: [...unionEnum.flattenedMembers.values()].map((m) => String(m.value)),
      };
    }
    return { typeName: "union" };
  }
  if (type.kind === "Model") {
    return { typeName: type.name || "object" };
  }
  return { typeName: type.kind.toLowerCase() };
}

function detectExternalDependencyFromTypeSpec(
  program: Program,
  propertyPath: string,
  propType: Type,
  description: string,
): ExternalDependencyHint | undefined {
  const lowerPath = propertyPath.toLowerCase();
  const armIdConfig =
    propType.kind === "Scalar" ? getArmResourceIdentifierConfig(program, propType) : undefined;
  const armAllowed = armIdConfig?.allowedResources?.[0]?.type;

  if (lowerPath === "identity" || lowerPath.endsWith(".userassignedidentities")) {
    return {
      propertyPath,
      providerNamespace: "Microsoft.ManagedIdentity",
      kind: "managed-identity",
      required: false,
      description: "User-assigned or system-assigned Managed Identity fixture",
    };
  }
  if (
    lowerPath.includes("subnetid") ||
    lowerPath.includes("virtualnetwork") ||
    armAllowed?.toLowerCase().startsWith("microsoft.network/virtualnetworks")
  ) {
    return {
      propertyPath,
      providerNamespace: "Microsoft.Network",
      kind: "vnet-subnet",
      required: false,
      description,
    };
  }
  if (
    lowerPath.includes("privateendpoint") ||
    armAllowed?.toLowerCase().startsWith("microsoft.network/privateendpoints")
  ) {
    return {
      propertyPath,
      providerNamespace: "Microsoft.Network",
      kind: "private-endpoint",
      required: false,
      description,
    };
  }
  if (
    lowerPath.includes("keyvault") ||
    lowerPath.includes("vaulturi") ||
    lowerPath.includes("keyidentifier") ||
    armAllowed?.toLowerCase().startsWith("microsoft.keyvault/")
  ) {
    return {
      propertyPath,
      providerNamespace: "Microsoft.KeyVault",
      kind: "key-vault",
      required: false,
      description,
    };
  }
  if (
    lowerPath.includes("storageaccount") ||
    armAllowed?.toLowerCase().startsWith("microsoft.storage/")
  ) {
    return {
      propertyPath,
      providerNamespace: "Microsoft.Storage",
      kind: "storage-account",
      required: false,
      description,
    };
  }
  if (
    lowerPath.includes("workspaceid") ||
    lowerPath.includes("workspaceresourceid") ||
    armAllowed?.toLowerCase().startsWith("microsoft.operationalinsights/")
  ) {
    return {
      propertyPath,
      providerNamespace: "Microsoft.OperationalInsights",
      kind: "log-analytics",
      required: false,
      description,
    };
  }
  if ((lowerPath.endsWith("resourceid") || Boolean(armIdConfig)) && !lowerPath.includes("parent")) {
    return {
      propertyPath,
      providerNamespace: armAllowed?.split("/")[0],
      kind: "generic-arm-resource",
      required: false,
      description,
    };
  }
  return undefined;
}

function hasWireJsonBody(
  program: Program,
  metadataInfo: MetadataInfo,
  type: Type | undefined,
  visibility: Visibility,
): boolean {
  if (!type || isVoidType(type)) {
    return false;
  }
  if (type.kind !== "Model") {
    return true;
  }
  if (
    isArrayModelType(program, type) ||
    isRecordModelType(program, type) ||
    Boolean(type.indexer)
  ) {
    return true;
  }
  for (const prop of walkPropertiesInherited(type)) {
    if (metadataInfo.isPayloadProperty(prop, visibility)) {
      return true;
    }
  }
  return false;
}

function collectTypeSpecBodyMetadata(
  program: Program,
  metadataInfo: MetadataInfo,
  reqVisibility: Visibility,
  type: Type | undefined,
  prefix = "",
  depth = 0,
  ancestors = new Set<Type>(),
  result = {
    writable: new Set<string>(),
    readOnly: new Set<string>(),
    secrets: new Set<string>(),
    externalDeps: new Map<string, ExternalDependencyHint>(),
  },
  requiredInParent = false,
): {
  writable: Set<string>;
  readOnly: Set<string>;
  secrets: Set<string>;
  externalDeps: Map<string, ExternalDependencyHint>;
} {
  if (!type || ancestors.has(type)) {
    return result;
  }
  const branchAncestors = new Set(ancestors);
  branchAncestors.add(type);

  if (type.kind === "Model") {
    if (isArrayModelType(program, type)) {
      const arrayPrefix = prefix ? `${prefix}[]` : "[]";
      if (isSecret(program, type.indexer.value)) {
        result.secrets.add(arrayPrefix);
      }
      collectTypeSpecBodyMetadata(
        program,
        metadataInfo,
        reqVisibility | Visibility.Item,
        type.indexer.value,
        arrayPrefix,
        depth + 1,
        branchAncestors,
        result,
        false,
      );
      return result;
    }
    if (isRecordModelType(program, type)) {
      const recordPrefix = prefix ? `${prefix}.*` : "*";
      if (isSecret(program, type.indexer.value)) {
        result.secrets.add(recordPrefix);
      }
      collectTypeSpecBodyMetadata(
        program,
        metadataInfo,
        reqVisibility | Visibility.Item,
        type.indexer.value,
        recordPrefix,
        depth + 1,
        branchAncestors,
        result,
        false,
      );
      return result;
    }

    for (const prop of walkPropertiesInherited(type)) {
      const wireName = resolveEncodedName(program, prop, "application/json");
      const propPath = prefix ? `${prefix}.${wireName}` : wireName;
      const readOnly = isReadonlyProperty(program, prop);
      const visibleInReq = metadataInfo.isPayloadProperty(prop, reqVisibility);
      const visibleInRead = metadataInfo.isPayloadProperty(prop, Visibility.Read);

      if (readOnly || (!visibleInReq && visibleInRead)) {
        result.readOnly.add(propPath);
      } else if (
        depth <= 7 &&
        visibleInReq &&
        visibleInRead &&
        !propPath.includes("[]") &&
        !propPath.includes(".*") &&
        propPath !== "id" &&
        propPath !== "name" &&
        propPath !== "type" &&
        propPath !== "systemData"
      ) {
        result.writable.add(propPath);
      }

      if (
        isSecret(program, prop) ||
        isSecret(program, prop.type) ||
        SECRET_PROPERTY_NAME_RE.test(wireName)
      ) {
        result.secrets.add(propPath);
      }

      const isPropRequired = !prop.optional && !metadataInfo.isOptional(prop, reqVisibility);
      const doc = getDoc(program, prop) ?? "";
      const depHint = detectExternalDependencyFromTypeSpec(program, propPath, prop.type, doc);
      if (depHint && !result.externalDeps.has(propPath)) {
        result.externalDeps.set(propPath, {
          ...depHint,
          required: requiredInParent && isPropRequired,
        });
      }

      if (visibleInReq || visibleInRead) {
        collectTypeSpecBodyMetadata(
          program,
          metadataInfo,
          reqVisibility,
          prop.type,
          propPath,
          depth + 1,
          branchAncestors,
          result,
          requiredInParent ? isPropRequired : depth === 0 ? isPropRequired : false,
        );
      }
    }

    // Also traverse derived models at the same payload path so discriminated subtype-only @secret properties are discovered (#4008)!
    for (const derived of type.derivedModels) {
      collectTypeSpecBodyMetadata(
        program,
        metadataInfo,
        reqVisibility,
        derived,
        prefix,
        depth,
        branchAncestors,
        result,
        false,
      );
    }
  } else if (type.kind === "Union") {
    for (const variant of type.variants.values()) {
      collectTypeSpecBodyMetadata(
        program,
        metadataInfo,
        reqVisibility,
        variant.type,
        prefix,
        depth,
        branchAncestors,
        result,
        requiredInParent,
      );
    }
  }

  return result;
}

function collectTypeSpecResponseSecrets(
  program: Program,
  httpOp: HttpOperation,
): { bodySecrets: string[]; headerSecrets: string[]; secretStatusCodes: string[] } {
  const secrets = new Set<string>();
  const headerSecrets = new Set<string>();
  const secretStatusCodes = new Set<string>();

  function walk(type: Type | undefined, prefix = "", depth = 0, ancestors = new Set<Type>()): void {
    if (!type || ancestors.has(type)) {
      return;
    }
    const branchAncestors = new Set(ancestors);
    branchAncestors.add(type);

    if (type.kind === "Model") {
      if (isArrayModelType(program, type)) {
        const arrayPrefix = prefix ? `${prefix}[]` : "[]";
        if (isSecret(program, type.indexer.value)) {
          secrets.add(arrayPrefix);
        }
        walk(type.indexer.value, arrayPrefix, depth + 1, branchAncestors);
        return;
      }
      if (isRecordModelType(program, type)) {
        const recordPrefix = prefix ? `${prefix}.*` : "*";
        if (isSecret(program, type.indexer.value)) {
          secrets.add(recordPrefix);
        }
        walk(type.indexer.value, recordPrefix, depth + 1, branchAncestors);
        return;
      }
      for (const prop of walkPropertiesInherited(type)) {
        const wireName = resolveEncodedName(program, prop, "application/json");
        const propPath = prefix ? `${prefix}.${wireName}` : wireName;
        if (
          isSecret(program, prop) ||
          isSecret(program, prop.type) ||
          SECRET_PROPERTY_NAME_RE.test(wireName)
        ) {
          secrets.add(propPath);
        }
        walk(prop.type, propPath, depth + 1, branchAncestors);
      }
      for (const derived of type.derivedModels) {
        walk(derived, prefix, depth, branchAncestors);
      }
    } else if (type.kind === "Union") {
      for (const variant of type.variants.values()) {
        walk(variant.type, prefix, depth, branchAncestors);
      }
    }
  }

  for (const resp of httpOp.responses) {
    const respCodes: string[] = [];
    if (typeof resp.statusCodes === "number") {
      respCodes.push(String(resp.statusCodes));
    } else if (typeof resp.statusCodes === "object") {
      for (let c = resp.statusCodes.start; c <= resp.statusCodes.end; c++) {
        respCodes.push(String(c));
      }
    }

    for (const content of resp.responses) {
      for (const [hWireName, hProp] of Object.entries(content.headers ?? {})) {
        if (
          isSecret(program, hProp) ||
          isSecret(program, hProp.type) ||
          SECRET_PROPERTY_NAME_RE.test(hWireName) ||
          SECRET_PROPERTY_NAME_RE.test(hProp.name)
        ) {
          headerSecrets.add(hWireName);
          secrets.add(hWireName);
        }
      }
      if (content.body) {
        const isWholeBodySecret =
          (content.body.property ? isSecret(program, content.body.property) : false) ||
          isSecret(program, content.body.type);
        if (isWholeBodySecret) {
          for (const code of respCodes) {
            secretStatusCodes.add(code);
          }
        }
        walk(content.body.type);
      }
    }
  }
  return {
    bodySecrets: [...secrets],
    headerSecrets: [...headerSecrets],
    secretStatusCodes: [...secretStatusCodes],
  };
}

function extractPaginationContractsFromTypeSpec(
  program: Program,
  httpOp: HttpOperation,
): { declaredPageable?: PageableContract; inferredPagination?: PageableContract } {
  const [paging] = getPagingOperation(program, httpOp.operation);
  if (paging) {
    const itemName = resolveEncodedName(
      program,
      paging.output.pageItems.property,
      "application/json",
    );
    const nextLinkName = paging.output.nextLink
      ? resolveEncodedName(program, paging.output.nextLink.property, "application/json")
      : null;
    return { declaredPageable: { itemName, nextLinkName } };
  }

  const openApiExtensions = getExtensions(program, httpOp.operation);
  const xMsPageable = openApiExtensions.get("x-ms-pageable") as
    | { itemName?: string; nextLinkName?: string | null }
    | undefined;
  if (xMsPageable && typeof xMsPageable === "object") {
    return {
      declaredPageable: {
        itemName: xMsPageable.itemName ?? "value",
        nextLinkName: xMsPageable.nextLinkName ?? "nextLink",
      },
    };
  }

  // Keep undecorated { value: T[], nextLink?: string } traversal hints separate from declared `pageable`
  // so missing @list / x-ms-pageable metadata still triggers PAGEABLE-CONTRACT-DRIFT (#8233)!
  if (httpOp.verb === "get") {
    const okResp = httpOp.responses.find((r) => r.statusCodes === 200);
    const bodyType = okResp?.responses.find((c) => c.body !== undefined)?.body?.type;
    if (bodyType?.kind === "Model") {
      let hasValueArray = false;
      let hasNextLink = false;
      for (const prop of walkPropertiesInherited(bodyType)) {
        const wireName = resolveEncodedName(program, prop, "application/json");
        if (
          wireName === "value" &&
          prop.type.kind === "Model" &&
          isArrayModelType(program, prop.type)
        ) {
          hasValueArray = true;
        }
        if (wireName === "nextLink") {
          hasNextLink = true;
        }
      }
      if (hasValueArray && hasNextLink) {
        return { inferredPagination: { itemName: "value", nextLinkName: "nextLink" } };
      }
    }
  }

  return {};
}

function scanExistingTypeSpecExamples(
  typespecProjectDir: string,
  apiVersion: string,
): Map<string, Array<{ title: string; filePath: string }>> {
  const index = new Map<string, Array<{ title: string; filePath: string }>>();
  const examplesDir = path.join(typespecProjectDir, "examples", apiVersion);
  if (!fs.existsSync(examplesDir)) {
    return index;
  }

  const stack = [examplesDir];
  while (stack.length > 0) {
    const dir = stack.shift()!;
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile() && entry.name.endsWith(".json")) {
        try {
          const parsed = JSON.parse(fs.readFileSync(full, "utf8")) as {
            operationId?: string;
            title?: string;
          };
          if (parsed.operationId) {
            const key = parsed.operationId;
            const list = index.get(key) ?? [];
            list.push({
              title: parsed.title ?? path.basename(full, ".json"),
              filePath: full,
            });
            index.set(key, list);
          }
        } catch {
          // Ignore malformed JSON in examples directory.
        }
      }
    }
  }
  return index;
}

const PHASE_PRIORITY: Record<LifecyclePhase, number> = {
  "preflight-discovery": 1,
  "external-fixture": 2,
  "negative-precheck": 3,
  create: 4,
  read: 5,
  list: 6,
  update: 7,
  action: 8,
  delete: 9,
  "deleted-resource": 10,
};

export function computeTopologicalExecutionOrder(operations: OperationContract[]): string[] {
  return [...operations]
    .sort((a, b) => {
      const aIsPreflight = a.phase === "preflight-discovery" ? 0 : 1;
      const bIsPreflight = b.phase === "preflight-discovery" ? 0 : 1;
      if (aIsPreflight !== bIsPreflight) {
        return aIsPreflight - bIsPreflight;
      }

      const aIsDeleted = a.phase === "deleted-resource" ? 1 : 0;
      const bIsDeleted = b.phase === "deleted-resource" ? 1 : 0;
      if (aIsDeleted !== bIsDeleted) {
        return aIsDeleted - bIsDeleted;
      }

      const aIsDelete = a.phase === "delete" ? 1 : 0;
      const bIsDelete = b.phase === "delete" ? 1 : 0;
      if (aIsDelete !== bIsDelete) {
        return aIsDelete - bIsDelete;
      }

      // For delete operations, delete deeper child resources BEFORE parent resources!
      if (a.phase === "delete" && b.phase === "delete" && a.depth !== b.depth) {
        return b.depth - a.depth;
      }

      // For positive lifecycle operations, create/read/update/action parent resources BEFORE children!
      if (a.depth !== b.depth) {
        return a.depth - b.depth;
      }

      const phaseDiff = PHASE_PRIORITY[a.phase] - PHASE_PRIORITY[b.phase];
      if (phaseDiff !== 0) {
        return phaseDiff;
      }

      return a.operationId.localeCompare(b.operationId);
    })
    .map((op) => op.operationId);
}

export async function fetchProviderLiveMetadata(options: {
  armBaseUrl: string;
  subscriptionId: string;
  providerNamespace: string;
  targetApiVersion: string;
  bearerToken?: string;
}): Promise<ProviderLiveMetadata> {
  const token = getArmBearerToken({
    explicitToken: options.bearerToken,
    subscriptionId: options.subscriptionId,
  });
  const base = options.armBaseUrl.replace(/\/+$/, "");
  const url = `${base}/subscriptions/${encodeURIComponent(options.subscriptionId)}/providers/${encodeURIComponent(options.providerNamespace)}?api-version=2021-04-01`;
  assertTrustedArmOrigin(url, options.armBaseUrl);
  const resp = await fetch(url, {
    headers: {
      Accept: "application/json",
      Authorization: `Bearer ${token}`,
    },
    signal: AbortSignal.timeout(30_000),
  });

  if (!resp.ok) {
    throw new Error(
      `Failed to query live ARM provider metadata for ${options.providerNamespace}: HTTP ${resp.status}`,
    );
  }

  const data = (await resp.json()) as {
    namespace?: string;
    registrationState?: string;
    resourceTypes?: Array<{
      resourceType?: string;
      apiVersions?: string[];
      defaultApiVersion?: string;
      locations?: string[];
    }>;
  };

  const resourceTypes = (data.resourceTypes ?? [])
    .filter((rt) => Boolean(rt.resourceType))
    .map((rt) => ({
      resourceType: rt.resourceType!,
      apiVersions: rt.apiVersions ?? [],
      defaultApiVersion: rt.defaultApiVersion,
      locations: rt.locations ?? [],
    }));

  const targetVersionSupportedOnArm = resourceTypes.some((rt) =>
    rt.apiVersions.includes(options.targetApiVersion),
  );

  const locationCounts = new Map<string, number>();
  for (const rt of resourceTypes) {
    for (const loc of rt.locations) {
      const normalized = loc.toLowerCase().replace(/\s+/g, "");
      if (normalized && normalized !== "global") {
        locationCounts.set(normalized, (locationCounts.get(normalized) ?? 0) + 1);
      }
    }
  }
  const preferredOrder = ["eastus", "eastus2", "westus2", "westus3", "centralus", "westeurope"];
  const recommendedLocations = preferredOrder.filter((loc) => locationCounts.has(loc));
  if (recommendedLocations.length === 0) {
    recommendedLocations.push(...[...locationCounts.keys()].slice(0, 5));
  }

  return {
    namespace: data.namespace ?? options.providerNamespace,
    registrationState: data.registrationState,
    resourceTypes,
    targetVersionSupportedOnArm,
    recommendedLocations,
  };
}

export async function discoverSpecInventory(
  options: DiscoverInventoryOptions,
): Promise<CoverageLedger> {
  if (fs.existsSync(getLedgerPath(options.workDir))) {
    const existingLedger = loadLedger(options.workDir);
    const activeRg = existingLedger.disposableResourceGroup;
    if (
      activeRg &&
      activeRg.cleanupStatus !== "deleted" &&
      activeRg.cleanupStatus !== "not_created"
    ) {
      throw new Error(
        `Refusing to overwrite "${options.workDir}/coverage-ledger.json" while disposable Resource Group "${activeRg.name}" has cleanupStatus "${activeRg.cleanupStatus}". Run "rg delete" first or choose a fresh --work-dir.`,
      );
    }
    if (!options.reset) {
      throw new Error(
        `Work directory "${options.workDir}" already contains coverage-ledger.json. Pass --reset (after RG cleanup) or choose a fresh --work-dir so stale traces are not mixed.`,
      );
    }
    fs.rmSync(path.join(options.workDir, TRACES_DIRNAME), { recursive: true, force: true });
    fs.rmSync(path.join(options.workDir, GENERATED_EXAMPLES_DIRNAME), {
      recursive: true,
      force: true,
    });
  }

  const service = await loadProjectedTypeSpecService(options.specPath, options.apiVersion);
  const {
    program,
    tcgcContext,
    typespecProjectDir,
    entrypointFile,
    apiVersion,
    availableApiVersions,
    httpOperations,
  } = service;
  const armBaseUrl = (options.armBaseUrl ?? "https://management.azure.com").replace(/\/+$/, "");

  const metadataInfo = createMetadataInfo(program);
  const existingExamplesIndex = scanExistingTypeSpecExamples(typespecProjectDir, apiVersion);

  const operationsMap: Record<string, OperationContract> = {};
  const externalDepsMap = new Map<string, ExternalDependencyHint>();
  let detectedNamespace = service.providerNamespace;

  for (const httpOp of httpOperations) {
    const method = httpOp.verb.toUpperCase() as HttpMethod;
    const pathTemplate = httpOp.path;
    const operationId = resolveCanonicalOperationId(tcgcContext, program, httpOp.operation);
    const sourceLocation = extractOperationSourceLocation(httpOp.operation);

    const { providerNamespace, resourceType, depth } = extractProviderAndResource(
      pathTemplate,
      method,
    );
    if (providerNamespace !== "Microsoft.Resources" && providerNamespace !== "Unknown.Provider") {
      detectedNamespace = providerNamespace;
    }

    const { declaredPageable: pageable, inferredPagination } =
      extractPaginationContractsFromTypeSpec(program, httpOp);
    const lroMeta = getLroMetadata(program, httpOp.operation);
    const openApiExtensions = getExtensions(program, httpOp.operation);
    const isLroDeclared =
      Boolean(lroMeta) || openApiExtensions.get("x-ms-long-running-operation") === true;
    const lroFinalStateVia = lroMeta?.finalStateVia;

    const reqVisibility = resolveRequestVisibility(program, httpOp.operation, httpOp.verb);
    const respSecrets = collectTypeSpecResponseSecrets(program, httpOp);
    const secretProperties = new Set<string>(respSecrets.bodySecrets);
    const secretResponseHeaders = new Set<string>(respSecrets.headerSecrets);
    let writableBodyProperties: string[] = [];
    let readOnlyBodyProperties: string[] = [];
    const opExternalDeps: ExternalDependencyHint[] = [];
    const paramSpecs: OperationParameterSpec[] = [];

    for (const p of httpOp.parameters.parameters) {
      if (p.type === "cookie") {
        continue;
      }
      const desc = describeTypeSpecType(p.param.type);
      const format = getFormat(program, p.param) ?? getFormat(program, p.param.type);
      const pattern = getPattern(program, p.param) ?? getPattern(program, p.param.type);
      const minLength = getMinLength(program, p.param) ?? getMinLength(program, p.param.type);
      const maxLength = getMaxLength(program, p.param) ?? getMaxLength(program, p.param.type);
      const allowReserved =
        p.type === "path" && "allowReserved" in p ? Boolean(p.allowReserved) : undefined;
      const isSecretParam =
        isSecret(program, p.param) ||
        isSecret(program, p.param.type) ||
        SECRET_PROPERTY_NAME_RE.test(p.name);
      if (isSecretParam) {
        secretProperties.add(p.name);
      }

      paramSpecs.push({
        name: p.name,
        in: p.type,
        required: !p.param.optional,
        type: desc.typeName,
        format,
        pattern,
        minLength,
        maxLength,
        ...(allowReserved !== undefined ? { allowReserved } : {}),
        enumValues: desc.enumValues,
        readOnly: isReadonlyProperty(program, p.param),
        secretCandidate: isSecretParam,
        externalResourceReference: p.name.toLowerCase().endsWith("resourceid")
          ? "generic-arm-resource"
          : undefined,
      });
    }

    const reqBody = httpOp.parameters.body;
    if (reqBody && hasWireJsonBody(program, metadataInfo, reqBody.type, reqVisibility)) {
      const bodyParamName = resolveBodyParameterName(tcgcContext, reqBody.property);
      const bodyRequired = reqBody.property ? !reqBody.property.optional : true;
      const bodyMeta = collectTypeSpecBodyMetadata(
        program,
        metadataInfo,
        reqVisibility,
        reqBody.type,
        "",
        0,
        new Set<Type>(),
        undefined,
        bodyRequired,
      );
      writableBodyProperties = [...bodyMeta.writable].sort();
      readOnlyBodyProperties = [...bodyMeta.readOnly].sort();
      for (const s of bodyMeta.secrets) {
        secretProperties.add(s);
      }
      for (const dep of bodyMeta.externalDeps.values()) {
        opExternalDeps.push(dep);
        const depKey = `${dep.kind}:${dep.propertyPath}`;
        if (!externalDepsMap.has(depKey)) {
          externalDepsMap.set(depKey, dep);
        }
      }

      const bodyDesc = describeTypeSpecType(reqBody.type);
      const isSecretBody =
        (reqBody.property ? isSecret(program, reqBody.property) : false) ||
        isSecret(program, reqBody.type);
      if (isSecretBody) {
        secretProperties.add(bodyParamName);
      }
      paramSpecs.push({
        name: bodyParamName,
        in: "body",
        required: bodyRequired,
        type: bodyDesc.typeName,
        secretCandidate: isSecretBody,
      });
    }

    const declaredStatusCodesSet = new Set<string>();
    const declaredResponseHeaders: Record<string, string[]> = {};
    const declaredRequiredResponseHeaders: Record<string, string[][]> = {};
    const declaredResponseHasSchema: Record<string, boolean> = {};
    let hasDefaultErrorResponse = false;

    for (const resp of httpOp.responses) {
      if (resp.statusCodes === "*" || isErrorModel(program, resp.type)) {
        hasDefaultErrorResponse = true;
        if (resp.statusCodes === "*") {
          continue;
        }
      }

      const codes: string[] = [];
      if (typeof resp.statusCodes === "number") {
        codes.push(String(resp.statusCodes));
      } else if (typeof resp.statusCodes === "object") {
        for (let c = resp.statusCodes.start; c <= resp.statusCodes.end; c++) {
          codes.push(String(c));
        }
      }

      const headerSet = new Set<string>();
      const contentRequiredAlts: string[][] = [];
      let hasBodySchema = false;
      for (const content of resp.responses) {
        const reqHeadersForAlt: string[] = [];
        for (const [hName, hProp] of Object.entries(content.headers ?? {})) {
          const lowerH = hName.toLowerCase();
          headerSet.add(lowerH);
          if (!hProp.optional) {
            reqHeadersForAlt.push(lowerH);
          }
        }
        contentRequiredAlts.push(reqHeadersForAlt.sort());
        if (content.body && !isVoidType(content.body.type)) {
          hasBodySchema = true;
        }
      }

      for (const code of codes) {
        declaredStatusCodesSet.add(code);
        if (headerSet.size > 0) {
          const merged = new Set([...(declaredResponseHeaders[code] ?? []), ...headerSet]);
          declaredResponseHeaders[code] = [...merged].sort();
        }
        if (contentRequiredAlts.length > 0) {
          declaredRequiredResponseHeaders[code] = [
            ...(declaredRequiredResponseHeaders[code] ?? []),
            ...contentRequiredAlts,
          ];
        }
        declaredResponseHasSchema[code] = Boolean(declaredResponseHasSchema[code]) || hasBodySchema;
      }
    }

    const matchedExamples = existingExamplesIndex.get(operationId) ?? [];

    operationsMap[operationId] = {
      operationId,
      method,
      pathTemplate,
      typespecProjectDir,
      entrypointFile,
      sourceLocation,
      apiVersion,
      scope: inferScope(pathTemplate),
      resourceType,
      depth,
      phase: classifyPhase(method, pathTemplate, operationId, pageable ?? inferredPagination),
      declaredStatusCodes: [...declaredStatusCodesSet].sort(),
      declaredResponseHeaders,
      ...(Object.keys(declaredRequiredResponseHeaders).length > 0
        ? { declaredRequiredResponseHeaders }
        : {}),
      declaredResponseHasSchema,
      isLroDeclared,
      lroFinalStateVia,
      pageable,
      ...(inferredPagination ? { inferredPagination } : {}),
      hasDefaultErrorResponse,
      parameters: paramSpecs,
      writableBodyProperties,
      readOnlyBodyProperties,
      secretProperties: [...secretProperties].sort(),
      ...(secretResponseHeaders.size > 0
        ? { secretResponseHeaders: [...secretResponseHeaders].sort() }
        : {}),
      ...(respSecrets.secretStatusCodes.length > 0
        ? { secretResponseStatuses: [...respSecrets.secretStatusCodes].sort() }
        : {}),
      externalDependencies: opExternalDeps,
      existingExampleNames: matchedExamples.map((e) => e.title),
      existingExamplePaths: matchedExamples.map((e) => e.filePath),
    };
  }

  const allOperations = Object.values(operationsMap);

  // Pair resource GET operations with their sibling PUT contracts so post-create GET round-trip
  // mutability validation knows which properties were writable vs. read-only on PUT (#26 / #27).
  for (const op of allOperations) {
    if (op.method === "GET" && !op.pageable && op.writableBodyProperties.length === 0) {
      const normalizedGetPath = op.pathTemplate.split("?")[0].replace(/\/+$/, "").toLowerCase();
      const pairedPut =
        allOperations.find(
          (candidate) =>
            candidate.method === "PUT" &&
            candidate.pathTemplate.split("?")[0].replace(/\/+$/, "").toLowerCase() ===
              normalizedGetPath,
        ) ??
        allOperations.find(
          (candidate) =>
            candidate.method === "PUT" &&
            candidate.resourceType === op.resourceType &&
            candidate.depth === op.depth,
        );
      if (pairedPut) {
        op.writableBodyProperties = [...pairedPut.writableBodyProperties];
        if (op.readOnlyBodyProperties.length === 0) {
          op.readOnlyBodyProperties = [...pairedPut.readOnlyBodyProperties];
        }
        op.secretProperties = [
          ...new Set([...op.secretProperties, ...pairedPut.secretProperties]),
        ].sort();
      }
    }
  }

  const executionOrder = computeTopologicalExecutionOrder(allOperations);

  const coverage: Record<string, OperationCoverageEntry> = {};
  for (const opId of executionOrder) {
    const contract = operationsMap[opId];
    coverage[opId] = {
      operationId: opId,
      method: contract.method,
      pathTemplate: contract.pathTemplate,
      sourceLocation: contract.sourceLocation,
      phase: contract.phase,
      resourceType: contract.resourceType,
      status: "pending",
      attempts: 0,
      traceFiles: [],
      discrepancyCount: 0,
      generatedExamples: [],
    };
  }

  const normalizedProject = typespecProjectDir.replace(/\\/g, "/");
  const serviceMatch = /\/specification\/([^/]+)\//.exec(normalizedProject);
  const serviceName = serviceMatch?.[1] ?? detectedNamespace;

  let providerLiveMetadata: ProviderLiveMetadata | undefined;
  if (
    options.checkLiveProvider &&
    options.subscriptionId &&
    detectedNamespace !== "Unknown.Provider"
  ) {
    providerLiveMetadata = await fetchProviderLiveMetadata({
      armBaseUrl,
      subscriptionId: options.subscriptionId,
      providerNamespace: detectedNamespace,
      targetApiVersion: apiVersion,
      bearerToken: options.bearerToken,
    });
  }

  const now = new Date().toISOString();
  const ledger: CoverageLedger = {
    schemaVersion: "2.0-typespec",
    runId: crypto.randomBytes(4).toString("hex"),
    createdAt: now,
    updatedAt: now,
    serviceName,
    providerNamespace: detectedNamespace,
    apiVersion,
    availableApiVersions,
    typespecProjectDir,
    entrypointFile,
    subscriptionId: options.subscriptionId,
    location: options.location ?? providerLiveMetadata?.recommendedLocations[0],
    armBaseUrl,
    providerLiveMetadata,
    externalDependencies: [...externalDepsMap.values()],
    provisionedFixtures: [],
    runtimeState: {
      pathSlotValues: {},
      putBodiesByResourceType: {},
      listItemNamesByResourceType: {},
    },
    executionOrder,
    operations: operationsMap,
    coverage,
  };

  saveLedger(options.workDir, ledger);
  return ledger;
}
