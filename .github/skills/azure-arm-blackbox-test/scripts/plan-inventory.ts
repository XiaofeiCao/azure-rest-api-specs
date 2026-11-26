import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import {
  getArmResourceIdentifierConfig,
  getLroMetadata,
  getUnionAsEnum,
} from "@azure-tools/typespec-azure-core";
import {
  getDiscriminator,
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
import {
  assertTrustedArmOrigin,
  getArmBearerToken,
  inferArmTokenResource,
  resolveArmRelativeOrAbsoluteUrl,
  validateAndNormalizeAllowedArmOrigins,
  validateAndNormalizeArmBaseUrl,
} from "./auth-and-http.ts";
import {
  GENERATED_EXAMPLES_DIRNAME,
  getLedgerPath,
  loadLedger,
  saveLedger,
  TRACES_DIRNAME,
} from "./ledger-store.ts";
import { escapeSecretPropertySegment } from "./sanitize-example.ts";
import {
  extractOperationSourceLocation,
  loadProjectedTypeSpecService,
  resolveBodyParameterName,
  resolveCanonicalOperationId,
} from "./typespec-loader.ts";
import type {
  ArmOperationScope,
  CoverageLedger,
  ExecutionDag,
  ExecutionDagEdge,
  ExecutionDagNode,
  ExternalDependencyHint,
  HttpMethod,
  LifecyclePhase,
  OperationContract,
  OperationCoverageEntry,
  OperationParameterSpec,
  PageableContract,
  ProviderLiveMetadata,
  SecretCycleRule,
  SecretStringConstraint,
  ShardPartitionManifest,
} from "./types.ts";

const SECRET_PROPERTY_NAME_RE =
  /(password|secret|connectionstring|primarykey|secondarykey|accesskey|apikey|sastoken|sharedkey|clientsecret|privatekey|token)/i;

export interface DiscoverInventoryOptions {
  specPath: string;
  apiVersion?: string;
  workDir: string;
  armBaseUrl?: string;
  armTokenResource?: string;
  allowedArmOrigins?: string[];
  subscriptionId?: string;
  location?: string;
  resourceFilter?: string | string[];
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

function hasResourceInstanceSegmentInRoute(cleanPath: string): boolean {
  const providerIdx = cleanPath.toLowerCase().lastIndexOf("/providers/");
  if (providerIdx === -1) {
    return false;
  }
  const afterProviders = cleanPath.slice(providerIdx + "/providers/".length);
  const segments = afterProviders.split("/").filter(Boolean).slice(1);
  for (let i = 0; i < segments.length; i++) {
    if (
      segments[i].toLowerCase() === "locations" &&
      i + 1 < segments.length &&
      segments[i + 1].startsWith("{")
    ) {
      i++;
      continue;
    }
    if (segments[i].startsWith("{")) {
      return true;
    }
  }
  return false;
}

function classifyPhase(
  method: HttpMethod,
  pathTemplate: string,
  operationId: string,
  pageable: PageableContract | undefined,
): LifecyclePhase {
  const cleanPath = pathTemplate.split("?")[0].replace(/\/+$/, "");
  const lowerPath = cleanPath.toLowerCase();
  const lowerOp = operationId.toLowerCase();

  if (lowerPath.includes("/deleted") || lowerOp.includes("deleted")) {
    return "deleted-resource";
  }

  const hasInstanceKey = hasResourceInstanceSegmentInRoute(cleanPath);
  if (!hasInstanceKey) {
    if (method === "POST" && /\/check[a-z0-9]*(?:availability|visibility)$/i.test(lowerPath)) {
      return "preflight-discovery";
    }
    if (
      method === "GET" &&
      (lowerPath.endsWith("/operations") ||
        lowerOp.startsWith("operations_") ||
        /(?:^|\/)(?:usages|skus|quotas|capabilities|servicetags|servicetagdetails|bgpservicecommunities|expressrouteportslocations|expressrouteserviceproviders|available[a-z0-9_]*|[a-z0-9_]*available[a-z0-9_]*|check[a-z0-9]*(?:availability|visibility))(?:\/default|\/dafault)?$/i.test(
          lowerPath,
        ) ||
        /(?:check[a-z0-9]*(?:availability|visibility)|listskus|skus_list|quotas_list|capabilities_list|usages_list|^available|listavailable|servicetag)/i.test(
          lowerOp,
        ))
    ) {
      return "preflight-discovery";
    }
  }

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

function modelLooksLikeArmSubResourceRef(program: Program, candidate: Type): boolean {
  const unwrapped =
    candidate.kind === "Model" && isArrayModelType(program, candidate)
      ? candidate.indexer.value
      : candidate;
  if (unwrapped.kind !== "Model" || isRecordModelType(program, unwrapped)) {
    return false;
  }
  for (const p of walkPropertiesInherited(unwrapped)) {
    const wire = resolveEncodedName(program, p, "application/json");
    if (wire === "id" && !isReadonlyProperty(program, p)) {
      return true;
    }
  }
  return /^(SubResource|SubResourceModel|WritableSubResource)$/i.test(unwrapped.name ?? "");
}

function detectExternalDependencyFromTypeSpec(
  program: Program,
  propertyPath: string,
  wireName: string,
  propType: Type,
  description: string,
): ExternalDependencyHint | undefined {
  const lowerPath = propertyPath.toLowerCase();
  const lowerLeaf = wireName.toLowerCase();
  const unwrappedType =
    propType.kind === "Model" && isArrayModelType(program, propType)
      ? propType.indexer.value
      : propType;
  const armIdConfig =
    unwrappedType.kind === "Scalar"
      ? getArmResourceIdentifierConfig(program, unwrappedType)
      : undefined;
  const allowedTypes = (armIdConfig?.allowedResources ?? [])
    .map((r) => r.type)
    .filter((t): t is string => Boolean(t));
  const armAllowedPrimary = allowedTypes[0];

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
    lowerLeaf === "subnetid" ||
    lowerLeaf === "virtualnetworkid" ||
    allowedTypes.some((t) => t.toLowerCase().startsWith("microsoft.network/virtualnetworks"))
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
    lowerLeaf === "privateendpoint" ||
    lowerLeaf === "privateendpointconnections" ||
    allowedTypes.some((t) => t.toLowerCase().startsWith("microsoft.network/privateendpoints"))
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
    lowerLeaf.includes("keyvault") ||
    lowerLeaf === "vaulturi" ||
    lowerLeaf === "keyidentifier" ||
    allowedTypes.some((t) => t.toLowerCase().startsWith("microsoft.keyvault/"))
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
    lowerLeaf.includes("storageaccount") ||
    lowerLeaf === "storageid" ||
    allowedTypes.some((t) => t.toLowerCase().startsWith("microsoft.storage/"))
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
    lowerLeaf === "workspaceid" ||
    lowerLeaf === "workspaceresourceid" ||
    allowedTypes.some((t) => t.toLowerCase().startsWith("microsoft.operationalinsights/"))
  ) {
    return {
      propertyPath,
      providerNamespace: "Microsoft.OperationalInsights",
      kind: "log-analytics",
      required: false,
      description,
    };
  }
  if ((lowerLeaf.endsWith("resourceid") || Boolean(armIdConfig)) && !lowerLeaf.includes("parent")) {
    return {
      propertyPath,
      providerNamespace: armAllowedPrimary?.split("/")[0],
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

function extractStringConstraintFromPropOrType(
  program: Program,
  prop: { type: Type } & Type,
): SecretStringConstraint | undefined {
  let minLength = getMinLength(program, prop) ?? getMinLength(program, prop.type);
  let maxLength = getMaxLength(program, prop) ?? getMaxLength(program, prop.type);
  let pattern = getPattern(program, prop) ?? getPattern(program, prop.type);
  if (prop.type.kind === "Scalar") {
    let cur = prop.type.baseScalar;
    while (cur) {
      minLength ??= getMinLength(program, cur);
      maxLength ??= getMaxLength(program, cur);
      pattern ??= getPattern(program, cur);
      cur = cur.baseScalar;
    }
  }
  if (minLength === undefined && maxLength === undefined && pattern === undefined) {
    return undefined;
  }
  return {
    ...(minLength !== undefined ? { minLength } : {}),
    ...(maxLength !== undefined ? { maxLength } : {}),
    ...(pattern !== undefined ? { pattern } : {}),
  };
}

function recordCycleRuleIfRecurring(
  ancestorPaths: Map<Type, string>,
  type: Type,
  currentPrefix: string,
  cycleRules: Map<string, SecretCycleRule>,
): boolean {
  const priorPrefix = ancestorPaths.get(type);
  if (priorPrefix === undefined) {
    return false;
  }
  const relStep = priorPrefix
    ? currentPrefix.startsWith(`${priorPrefix}.`)
      ? currentPrefix.slice(priorPrefix.length + 1)
      : currentPrefix.startsWith(`${priorPrefix}[]`)
        ? currentPrefix.slice(priorPrefix.length)
        : undefined
    : currentPrefix || undefined;
  if (relStep) {
    cycleRules.set(`${priorPrefix}=>${relStep}`, {
      basePath: priorPrefix,
      repeatPath: relStep,
    });
  }
  return true;
}

const subtreeSecretCacheByProgram = new WeakMap<Program, Map<Type, boolean>>();

function typeSubtreeHasSecrets(program: Program, rootType: Type | undefined): boolean {
  if (!rootType) {
    return false;
  }
  let cache = subtreeSecretCacheByProgram.get(program);
  if (!cache) {
    cache = new Map<Type, boolean>();
    subtreeSecretCacheByProgram.set(program, cache);
  }
  const cached = cache.get(rootType);
  if (cached !== undefined) {
    return cached;
  }

  // Strongly-connected / cycle-safe reachability check over the finite TypeSpec type graph.
  const inProgress = new Set<Type>();
  function check(t: Type | undefined): boolean {
    if (!t) {
      return false;
    }
    const known = cache!.get(t);
    if (known !== undefined) {
      return known;
    }
    if (isSecret(program, t)) {
      cache!.set(t, true);
      return true;
    }
    if (inProgress.has(t)) {
      return false;
    }
    inProgress.add(t);
    let found = false;
    if (t.kind === "Model") {
      if (isArrayModelType(program, t) || isRecordModelType(program, t)) {
        found = isSecret(program, t.indexer.value) || check(t.indexer.value);
      } else {
        for (const prop of walkPropertiesInherited(t)) {
          const wireName = resolveEncodedName(program, prop, "application/json");
          if (
            isSecret(program, prop) ||
            isSecret(program, prop.type) ||
            SECRET_PROPERTY_NAME_RE.test(wireName) ||
            SECRET_PROPERTY_NAME_RE.test(prop.name) ||
            check(prop.type)
          ) {
            found = true;
            break;
          }
        }
        if (!found && getDiscriminator(program, t) !== undefined) {
          for (const derived of t.derivedModels) {
            if (check(derived)) {
              found = true;
              break;
            }
          }
        }
      }
    } else if (t.kind === "Union") {
      for (const v of t.variants.values()) {
        if (check(v.type)) {
          found = true;
          break;
        }
      }
    }
    inProgress.delete(t);
    // Only cache `false` when no active cycle dependency could flip the result; always cache `true`.
    if (found || inProgress.size === 0) {
      cache!.set(t, found);
    }
    return found;
  }

  return check(rootType);
}

function collectTypeSpecBodyMetadata(
  program: Program,
  metadataInfo: MetadataInfo,
  reqVisibility: Visibility,
  type: Type | undefined,
  prefix = "",
  depth = 0,
  ancestorPaths = new Map<Type, string>(),
  result = {
    writable: new Set<string>(),
    readOnly: new Set<string>(),
    secrets: new Set<string>(),
    secretConstraints: new Map<string, SecretStringConstraint>(),
    cycleRules: new Map<string, SecretCycleRule>(),
    externalDeps: new Map<string, ExternalDependencyHint>(),
    intraRpCandidateTokens: new Set<string>(),
    minNonSecretDepth: new Map<Type, number>(),
  },
  requiredInParent = false,
): {
  writable: Set<string>;
  readOnly: Set<string>;
  secrets: Set<string>;
  secretConstraints: Map<string, SecretStringConstraint>;
  cycleRules: Map<string, SecretCycleRule>;
  externalDeps: Map<string, ExternalDependencyHint>;
  intraRpCandidateTokens: Set<string>;
  minNonSecretDepth: Map<Type, number>;
} {
  if (!type) {
    return result;
  }
  if (recordCycleRuleIfRecurring(ancestorPaths, type, prefix, result.cycleRules)) {
    return result;
  }
  const hasSecrets = typeSubtreeHasSecrets(program, type);
  if (!hasSecrets) {
    if (depth > 7) {
      return result;
    }
    const prevDepth = result.minNonSecretDepth.get(type);
    if (prevDepth !== undefined && prevDepth <= depth) {
      return result;
    }
    result.minNonSecretDepth.set(type, depth);
  }
  const branchAncestors = new Map(ancestorPaths);
  branchAncestors.set(type, prefix);

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
      const escapedWireName = escapeSecretPropertySegment(wireName);
      const propPath = prefix ? `${prefix}.${escapedWireName}` : escapedWireName;
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

      const propConstraint = extractStringConstraintFromPropOrType(program, prop);
      if (
        isSecret(program, prop) ||
        isSecret(program, prop.type) ||
        SECRET_PROPERTY_NAME_RE.test(wireName)
      ) {
        result.secrets.add(propPath);
        if (propConstraint) {
          result.secretConstraints.set(propPath.toLowerCase(), propConstraint);
        }
      } else if (propConstraint && SECRET_PROPERTY_NAME_RE.test(prop.name)) {
        result.secretConstraints.set(propPath.toLowerCase(), propConstraint);
      }

      const isPropRequired = !prop.optional && !metadataInfo.isOptional(prop, reqVisibility);
      const doc = getDoc(program, prop) ?? "";
      const hasAncestorDep = [...result.externalDeps.keys()].some(
        (existingPath) =>
          propPath.startsWith(`${existingPath}.`) || propPath.startsWith(`${existingPath}[]`),
      );
      if (
        !hasAncestorDep &&
        (visibleInReq || wireName.toLowerCase() === "privateendpointconnections")
      ) {
        const depHint = detectExternalDependencyFromTypeSpec(
          program,
          propPath,
          wireName,
          prop.type,
          doc,
        );
        if (depHint && !result.externalDeps.has(propPath)) {
          result.externalDeps.set(propPath, {
            ...depHint,
            required: visibleInReq && !readOnly && requiredInParent && isPropRequired,
          });
        }
      }

      if (visibleInReq && !readOnly) {
        const unwrappedPropType =
          prop.type.kind === "Model" && isArrayModelType(program, prop.type)
            ? prop.type.indexer.value
            : prop.type;
        const armIdCfg =
          unwrappedPropType.kind === "Scalar"
            ? getArmResourceIdentifierConfig(program, unwrappedPropType)
            : undefined;
        for (const allowed of armIdCfg?.allowedResources ?? []) {
          if (allowed.type) {
            result.intraRpCandidateTokens.add(`type:${allowed.type.toLowerCase()}`);
          }
        }
        if (modelLooksLikeArmSubResourceRef(program, prop.type)) {
          result.intraRpCandidateTokens.add(`alias:${wireName.toLowerCase()}`);
          if (
            unwrappedPropType.kind === "Model" &&
            unwrappedPropType.name &&
            !/^(SubResource|SubResourceModel|WritableSubResource)$/i.test(unwrappedPropType.name)
          ) {
            result.intraRpCandidateTokens.add(`alias:${unwrappedPropType.name.toLowerCase()}`);
          }
        } else if (
          unwrappedPropType.kind === "Scalar" &&
          /id|ids$/i.test(wireName) &&
          !/^parent/i.test(wireName)
        ) {
          result.intraRpCandidateTokens.add(`alias:${wireName.toLowerCase()}`);
        }
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

    // Traverse derived models ONLY on @discriminator hierarchies so non-polymorphic base models
    // (e.g. SubResourceModel in Microsoft.Network with 60+ subclasses) never trigger O(k!) explosion!
    if (getDiscriminator(program, type) !== undefined) {
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
): {
  bodySecrets: string[];
  headerSecrets: string[];
  secretStatusCodes: string[];
  cycleRules: SecretCycleRule[];
  secretConstraints: Record<string, SecretStringConstraint>;
} {
  const secrets = new Set<string>();
  const headerSecrets = new Set<string>();
  const secretStatusCodes = new Set<string>();
  const cycleRules = new Map<string, SecretCycleRule>();
  const secretConstraints: Record<string, SecretStringConstraint> = {};

  function walk(
    type: Type | undefined,
    prefix = "",
    depth = 0,
    ancestorPaths = new Map<Type, string>(),
  ): void {
    if (!type) {
      return;
    }
    if (recordCycleRuleIfRecurring(ancestorPaths, type, prefix, cycleRules)) {
      return;
    }
    if (!typeSubtreeHasSecrets(program, type)) {
      return;
    }
    const branchAncestors = new Map(ancestorPaths);
    branchAncestors.set(type, prefix);

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
        const escapedWireName = escapeSecretPropertySegment(wireName);
        const propPath = prefix ? `${prefix}.${escapedWireName}` : escapedWireName;
        if (
          isSecret(program, prop) ||
          isSecret(program, prop.type) ||
          SECRET_PROPERTY_NAME_RE.test(wireName)
        ) {
          secrets.add(propPath);
          const constraint = extractStringConstraintFromPropOrType(program, prop);
          if (constraint) {
            secretConstraints[propPath.toLowerCase()] = constraint;
          }
        }
        walk(prop.type, propPath, depth + 1, branchAncestors);
      }
      if (getDiscriminator(program, type) !== undefined) {
        for (const derived of type.derivedModels) {
          walk(derived, prefix, depth, branchAncestors);
        }
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
          const constraint = extractStringConstraintFromPropOrType(program, hProp);
          if (constraint) {
            secretConstraints[hWireName.toLowerCase()] = constraint;
          }
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
    cycleRules: [...cycleRules.values()],
    secretConstraints,
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

function buildAliasVariantsForCollection(collectionSeg: string): string[] {
  const lower = collectionSeg.toLowerCase();
  const variants = new Set<string>([lower, `${lower}id`, `${lower}ids`]);
  let singular = lower;
  if (lower.endsWith("ies") && lower.length > 3) {
    singular = `${lower.slice(0, -3)}y`;
  } else if (/(?:ses|xes|ches|shes)$/.test(lower)) {
    singular = lower.slice(0, -2);
  } else if (lower.endsWith("s") && !lower.endsWith("ss") && lower.length > 2) {
    singular = lower.slice(0, -1);
  }
  variants.add(singular);
  variants.add(`${singular}id`);
  variants.add(`${singular}ids`);
  return [...variants];
}

function resolveIntraRpResourceDependencies(
  operations: OperationContract[],
  rawCandidateTokensByOp: Map<string, Set<string>>,
  providerNamespace: string,
): Map<string, Set<string>> {
  const creatableResourceTypes = new Map<string, { resourceType: string; depth: number }>();
  for (const op of operations) {
    if (op.phase === "create" && op.depth >= 1) {
      const key = op.resourceType.toLowerCase();
      const prev = creatableResourceTypes.get(key);
      if (!prev || op.depth < prev.depth) {
        creatableResourceTypes.set(key, { resourceType: op.resourceType, depth: op.depth });
      }
    }
  }

  const aliasToResourceType = new Map<string, { resourceType: string; depth: number }>();
  for (const entry of creatableResourceTypes.values()) {
    const leaf = entry.resourceType.split("/").pop()!;
    for (const alias of buildAliasVariantsForCollection(leaf)) {
      const existing = aliasToResourceType.get(alias);
      if (!existing || entry.depth < existing.depth) {
        aliasToResourceType.set(alias, entry);
      }
    }
  }

  // Map resourceType -> set of prerequisite intra-RP resourceTypes.
  const depsByResourceType = new Map<string, Set<string>>();
  for (const op of operations) {
    if (!depsByResourceType.has(op.resourceType)) {
      depsByResourceType.set(op.resourceType, new Set());
    }
    // Structural parent-child dependency: Microsoft.Foo/parents/children depends on Microsoft.Foo/parents.
    const parts = op.resourceType.split("/");
    if (parts.length >= 3) {
      const parentType = parts.slice(0, -1).join("/");
      const matchedParent = creatableResourceTypes.get(parentType.toLowerCase());
      if (matchedParent && matchedParent.resourceType !== op.resourceType) {
        depsByResourceType.get(op.resourceType)!.add(matchedParent.resourceType);
      }
    }
  }

  const nsPrefix = `${providerNamespace.toLowerCase()}/`;
  for (const op of operations) {
    if (op.phase !== "create") {
      continue;
    }
    const tokens = rawCandidateTokensByOp.get(op.operationId);
    if (!tokens || tokens.size === 0) {
      continue;
    }
    const opDeps = new Set<string>();
    const ownLower = op.resourceType.toLowerCase();
    for (const token of tokens) {
      let resolvedTarget: string | undefined;
      if (token.startsWith("type:")) {
        const tLower = token.slice("type:".length);
        if (tLower.startsWith(nsPrefix)) {
          resolvedTarget = creatableResourceTypes.get(tLower)?.resourceType;
        }
      } else if (token.startsWith("alias:")) {
        const alias = token.slice("alias:".length);
        resolvedTarget = aliasToResourceType.get(alias)?.resourceType;
      }
      if (!resolvedTarget) {
        continue;
      }
      const targetLower = resolvedTarget.toLowerCase();
      // Ignore self-references and inline child-collection properties (e.g. VirtualNetwork.properties.subnets).
      if (targetLower === ownLower || targetLower.startsWith(`${ownLower}/`)) {
        continue;
      }
      opDeps.add(resolvedTarget);
      depsByResourceType.get(op.resourceType)?.add(resolvedTarget);
    }
    if (opDeps.size > 0) {
      op.intraRpDependencies = [...opDeps].sort();
    }
  }

  return depsByResourceType;
}

function computeResourceTopoTiers(
  operations: OperationContract[],
  depsByResourceType: Map<string, Set<string>>,
): Map<string, number> {
  const allTypes = new Set<string>(operations.map((o) => o.resourceType));
  const minDepthByType = new Map<string, number>();
  for (const op of operations) {
    const prev = minDepthByType.get(op.resourceType);
    if (prev === undefined || op.depth < prev) {
      minDepthByType.set(op.resourceType, op.depth);
    }
  }

  const remaining = new Set<string>(allTypes);
  const tiers = new Map<string, number>();

  while (remaining.size > 0) {
    const ready: string[] = [];
    for (const rt of remaining) {
      const deps = depsByResourceType.get(rt);
      const hasUnplacedDep = deps ? [...deps].some((d) => remaining.has(d)) : false;
      if (!hasUnplacedDep) {
        ready.push(rt);
      }
    }

    if (ready.length === 0) {
      // Deterministic cycle-breaker: pick shallowest depth, then fewest unplaced deps, then alphabetical.
      const fallback = [...remaining].sort((a, b) => {
        const dDiff = (minDepthByType.get(a) ?? 1) - (minDepthByType.get(b) ?? 1);
        if (dDiff !== 0) return dDiff;
        const aUnplaced = [...(depsByResourceType.get(a) ?? [])].filter((d) =>
          remaining.has(d),
        ).length;
        const bUnplaced = [...(depsByResourceType.get(b) ?? [])].filter((d) =>
          remaining.has(d),
        ).length;
        if (aUnplaced !== bUnplaced) return aUnplaced - bUnplaced;
        return a.localeCompare(b);
      })[0];
      ready.push(fallback);
    }

    ready.sort((a, b) => a.localeCompare(b));
    for (const rt of ready) {
      let maxDepTier = -1;
      for (const dep of depsByResourceType.get(rt) ?? []) {
        const depTier = tiers.get(dep);
        if (depTier !== undefined && depTier > maxDepTier) {
          maxDepTier = depTier;
        }
      }
      tiers.set(rt, maxDepTier + 1);
      remaining.delete(rt);
    }
  }

  return tiers;
}

export function computeTopologicalExecutionOrder(
  operations: OperationContract[],
  depsByResourceType?: Map<string, Set<string>>,
): string[] {
  const effectiveDeps =
    depsByResourceType ?? resolveIntraRpResourceDependencies(operations, new Map(), "");
  const tiers = computeResourceTopoTiers(operations, effectiveDeps);

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

      const aTier = tiers.get(a.resourceType) ?? a.depth;
      const bTier = tiers.get(b.resourceType) ?? b.depth;

      // For delete operations, delete dependent & deeper child resources BEFORE prerequisite/parent resources!
      if (a.phase === "delete" && b.phase === "delete") {
        if (aTier !== bTier) {
          return bTier - aTier;
        }
        if (a.depth !== b.depth) {
          return b.depth - a.depth;
        }
        return a.operationId.localeCompare(b.operationId);
      }

      // For positive lifecycle operations, create/read/update/action prerequisite & parent resources BEFORE dependents/children!
      if (aTier !== bTier) {
        return aTier - bTier;
      }
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

function buildExecutionDag(
  operationsMap: Record<string, OperationContract>,
  executionOrder: string[],
  depsByResourceType: Map<string, Set<string>>,
  externalDeps: ExternalDependencyHint[],
): ExecutionDag {
  const allOps = Object.values(operationsMap);
  const tiers = computeResourceTopoTiers(allOps, depsByResourceType);
  const nodes: ExecutionDagNode[] = [];
  const edges: ExecutionDagEdge[] = [];
  const edgeKeys = new Set<string>();
  const addEdge = (from: string, to: string, reason: ExecutionDagEdge["reason"]): void => {
    if (!from || !to || from === to) return;
    const k = `${from}=>${to}:${reason}`;
    if (!edgeKeys.has(k)) {
      edgeKeys.add(k);
      edges.push({ from, to, reason });
    }
  };

  const fixtureKinds = new Set(externalDeps.map((d) => d.kind));
  for (const kind of fixtureKinds) {
    nodes.push({
      id: `fixture:${kind}`,
      kind: "external-fixture",
      fixtureKind: kind,
      phase: "external-fixture",
      topoTier: kind === "private-endpoint" ? 1 : 0,
    });
  }

  const createOpByResourceType = new Map<string, string>();
  const deleteOpByResourceType = new Map<string, string>();
  for (const opId of executionOrder) {
    const op = operationsMap[opId];
    if (!op) continue;
    if (op.phase === "create" && !createOpByResourceType.has(op.resourceType)) {
      createOpByResourceType.set(op.resourceType, opId);
    }
    if (op.phase === "delete" && !deleteOpByResourceType.has(op.resourceType)) {
      deleteOpByResourceType.set(op.resourceType, opId);
    }
    nodes.push({
      id: opId,
      kind: "operation",
      operationId: opId,
      resourceType: op.resourceType,
      phase: op.phase,
      topoTier: tiers.get(op.resourceType) ?? op.depth,
    });
  }

  for (const op of allOps) {
    const resCreate = createOpByResourceType.get(op.resourceType);
    const resDelete = deleteOpByResourceType.get(op.resourceType);
    if (
      resCreate &&
      op.phase !== "preflight-discovery" &&
      op.phase !== "create" &&
      op.phase !== "deleted-resource"
    ) {
      addEdge(resCreate, op.operationId, "create-before-lifecycle");
    }
    if (
      resDelete &&
      op.phase !== "preflight-discovery" &&
      op.phase !== "delete" &&
      op.phase !== "deleted-resource"
    ) {
      addEdge(op.operationId, resDelete, "lifecycle-before-delete");
    }
    for (const ext of op.externalDependencies) {
      const fixId = `fixture:${ext.kind}`;
      if (ext.kind === "private-endpoint" && resCreate) {
        addEdge(resCreate, fixId, "external-fixture-prereq");
        addEdge(fixId, op.operationId, "external-fixture-prereq");
      } else {
        addEdge(fixId, op.operationId, "external-fixture-prereq");
      }
    }
  }

  for (const [rt, prereqs] of depsByResourceType.entries()) {
    const depCreate = createOpByResourceType.get(rt);
    const depDelete = deleteOpByResourceType.get(rt);
    for (const prereqRt of prereqs) {
      const isParentChild = rt.toLowerCase().startsWith(`${prereqRt.toLowerCase()}/`);
      const prereqCreate = createOpByResourceType.get(prereqRt);
      const prereqDelete = deleteOpByResourceType.get(prereqRt);
      if (prereqCreate && depCreate) {
        addEdge(
          prereqCreate,
          depCreate,
          isParentChild ? "parent-before-child" : "intra-rp-resource-ref",
        );
      }
      if (depDelete && prereqDelete) {
        addEdge(
          depDelete,
          prereqDelete,
          isParentChild
            ? "child-delete-before-parent-delete"
            : "dependent-delete-before-prereq-delete",
        );
      }
    }
  }

  return { nodes, edges };
}

export async function fetchProviderLiveMetadata(options: {
  armBaseUrl: string;
  armTokenResource?: string;
  allowedArmOrigins?: string[];
  subscriptionId: string;
  providerNamespace: string;
  targetApiVersion: string;
  bearerToken?: string;
}): Promise<ProviderLiveMetadata> {
  const token = getArmBearerToken({
    explicitToken: options.bearerToken,
    subscriptionId: options.subscriptionId,
    armBaseUrl: options.armBaseUrl,
    tokenResource: options.armTokenResource,
  });
  const url = resolveArmRelativeOrAbsoluteUrl(
    options.armBaseUrl,
    `/subscriptions/${encodeURIComponent(options.subscriptionId)}/providers/${encodeURIComponent(options.providerNamespace)}?api-version=2021-04-01`,
  );
  assertTrustedArmOrigin(url, options.armBaseUrl, options.allowedArmOrigins);
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
  let preSeededLedger: CoverageLedger | undefined;
  if (fs.existsSync(getLedgerPath(options.workDir))) {
    const existingLedger = loadLedger(options.workDir);
    const activeRg =
      existingLedger.disposableResourceGroup &&
      existingLedger.disposableResourceGroup.cleanupStatus !== "deleted" &&
      existingLedger.disposableResourceGroup.cleanupStatus !== "not_created"
        ? existingLedger.disposableResourceGroup
        : undefined;
    const isRgOnlyPreSeeded =
      Object.keys(existingLedger.operations).length === 0 && !existingLedger.entrypointFile;

    if (isRgOnlyPreSeeded && !options.reset) {
      if (
        activeRg &&
        options.subscriptionId &&
        existingLedger.subscriptionId &&
        options.subscriptionId.toLowerCase() !== existingLedger.subscriptionId.toLowerCase()
      ) {
        throw new Error(
          `Cannot switch subscriptionId from "${existingLedger.subscriptionId}" to "${options.subscriptionId}" while disposable Resource Group "${activeRg.name}" has cleanupStatus "${activeRg.cleanupStatus}".`,
        );
      }
      if (activeRg && options.armBaseUrl) {
        const normalizedNewBase = validateAndNormalizeArmBaseUrl(options.armBaseUrl);
        if (normalizedNewBase.toLowerCase() !== existingLedger.armBaseUrl.toLowerCase()) {
          throw new Error(
            `Cannot switch armBaseUrl from "${existingLedger.armBaseUrl}" to "${normalizedNewBase}" while disposable Resource Group "${activeRg.name}" has cleanupStatus "${activeRg.cleanupStatus}".`,
          );
        }
      }
      preSeededLedger = existingLedger;
    } else {
      if (activeRg) {
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
  const armBaseUrl = options.armBaseUrl
    ? validateAndNormalizeArmBaseUrl(options.armBaseUrl)
    : preSeededLedger?.armBaseUrl
      ? validateAndNormalizeArmBaseUrl(preSeededLedger.armBaseUrl)
      : validateAndNormalizeArmBaseUrl(undefined);
  const parsedBase = new URL(armBaseUrl);
  const isLoopbackBase = parsedBase.protocol === "http:";
  const allowedArmOrigins = options.allowedArmOrigins
    ? validateAndNormalizeAllowedArmOrigins(options.allowedArmOrigins, isLoopbackBase)
    : validateAndNormalizeAllowedArmOrigins(preSeededLedger?.allowedArmOrigins, isLoopbackBase);
  const armTokenResource = options.armTokenResource
    ? inferArmTokenResource(armBaseUrl, options.armTokenResource)
    : (preSeededLedger?.armTokenResource ?? inferArmTokenResource(armBaseUrl, undefined));

  const metadataInfo = createMetadataInfo(program);
  const existingExamplesIndex = scanExistingTypeSpecExamples(typespecProjectDir, apiVersion);

  const operationsMap: Record<string, OperationContract> = {};
  const rawCandidateTokensByOp = new Map<string, Set<string>>();
  const namespaceVotes = new Map<string, number>();

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
      namespaceVotes.set(providerNamespace, (namespaceVotes.get(providerNamespace) ?? 0) + 1);
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
    const secretConstraints: Record<string, SecretStringConstraint> = {
      ...respSecrets.secretConstraints,
    };
    const secretCycleRulesMap = new Map<string, SecretCycleRule>();
    for (const rule of respSecrets.cycleRules) {
      secretCycleRulesMap.set(`${rule.basePath}=>${rule.repeatPath}`, rule);
    }
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
        if (minLength !== undefined || maxLength !== undefined || pattern !== undefined) {
          secretConstraints[p.name.toLowerCase()] = {
            ...(minLength !== undefined ? { minLength } : {}),
            ...(maxLength !== undefined ? { maxLength } : {}),
            ...(pattern !== undefined ? { pattern } : {}),
          };
        }
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
        new Map<Type, string>(),
        undefined,
        bodyRequired,
      );
      writableBodyProperties = [...bodyMeta.writable].sort();
      readOnlyBodyProperties = [...bodyMeta.readOnly].sort();
      for (const s of bodyMeta.secrets) {
        secretProperties.add(s);
      }
      for (const [cKey, cVal] of bodyMeta.secretConstraints.entries()) {
        secretConstraints[cKey] = cVal;
      }
      for (const [rKey, rVal] of bodyMeta.cycleRules.entries()) {
        secretCycleRulesMap.set(rKey, rVal);
      }
      for (const dep of bodyMeta.externalDeps.values()) {
        opExternalDeps.push(dep);
      }
      if (bodyMeta.intraRpCandidateTokens.size > 0) {
        rawCandidateTokensByOp.set(operationId, bodyMeta.intraRpCandidateTokens);
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
      ...(secretCycleRulesMap.size > 0
        ? { secretCycleRules: [...secretCycleRulesMap.values()] }
        : {}),
      ...(Object.keys(secretConstraints).length > 0 ? { secretConstraints } : {}),
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

  const majorityRouteNamespace =
    [...namespaceVotes.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] ?? "Unknown.Provider";
  const detectedNamespace =
    service.providerNamespace &&
    service.providerNamespace !== "Unknown.Provider" &&
    service.providerNamespace !== "Microsoft.Resources"
      ? service.providerNamespace
      : majorityRouteNamespace;

  // Filter out self-RP hints from externalDependencies (intra-RP references belong in executionGraph,
  // not external cross-RP fixtures), and record cross-RP extension host scopes (e.g. Microsoft.Compute/cloudServices).
  const externalDepsMap = new Map<string, ExternalDependencyHint>();
  for (const op of Object.values(operationsMap)) {
    const providerMatches = [...op.pathTemplate.matchAll(/\/providers\/([^/]+)/gi)].map(
      (m) => m[1],
    );
    for (const hostNs of providerMatches) {
      if (
        hostNs.toLowerCase() !== detectedNamespace.toLowerCase() &&
        hostNs.toLowerCase() !== "microsoft.resources"
      ) {
        op.externalDependencies.push({
          propertyPath: "$hostScope",
          providerNamespace: hostNs,
          kind: "generic-arm-resource",
          required: true,
          description: `Extension route hosted under ${hostNs}`,
        });
      }
    }
    op.externalDependencies = op.externalDependencies.filter(
      (dep) =>
        !dep.providerNamespace ||
        dep.providerNamespace.toLowerCase() !== detectedNamespace.toLowerCase(),
    );
  }

  const unfilteredOperations = Object.values(operationsMap);
  const fullDepsByResourceType = resolveIntraRpResourceDependencies(
    unfilteredOperations,
    rawCandidateTokensByOp,
    detectedNamespace,
  );

  // Optional --resource-filter narrows operationsMap while automatically retaining transitive intra-RP
  // create/delete prerequisites so filtered runs remain self-contained in a fresh disposable RG.
  const rawResourceFilter = options.resourceFilter
    ? Array.isArray(options.resourceFilter)
      ? options.resourceFilter
      : [options.resourceFilter]
    : [];
  if (rawResourceFilter.length > 0) {
    const needles = rawResourceFilter
      .flatMap((f) => f.split(","))
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean);
    if (needles.length > 0) {
      const matchedOps = new Set<string>();
      const matchedTypes = new Set<string>();
      for (const op of unfilteredOperations) {
        const haystacks = [
          op.operationId.toLowerCase(),
          op.resourceType.toLowerCase(),
          op.pathTemplate.toLowerCase(),
        ];
        if (needles.some((n) => haystacks.some((h) => h.includes(n)))) {
          matchedOps.add(op.operationId);
          matchedTypes.add(op.resourceType);
        }
      }
      // Close over transitive prerequisite resourceTypes (create + delete contracts).
      const prereqTypes = new Set<string>();
      const queue = [...matchedTypes];
      while (queue.length > 0) {
        const cur = queue.shift()!;
        for (const depRt of fullDepsByResourceType.get(cur) ?? []) {
          if (!matchedTypes.has(depRt) && !prereqTypes.has(depRt)) {
            prereqTypes.add(depRt);
            queue.push(depRt);
          }
        }
      }
      for (const op of unfilteredOperations) {
        const keep =
          matchedOps.has(op.operationId) ||
          (prereqTypes.has(op.resourceType) && (op.phase === "create" || op.phase === "delete"));
        if (!keep) {
          delete operationsMap[op.operationId];
        }
      }
    }
  }

  const allOperations = Object.values(operationsMap);
  for (const op of allOperations) {
    for (const dep of op.externalDependencies) {
      const depKey = `${dep.kind}:${dep.providerNamespace ?? ""}:${dep.propertyPath}`;
      if (!externalDepsMap.has(depKey)) {
        externalDepsMap.set(depKey, dep);
      }
    }
  }

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

  const depsByResourceType = new Map<string, Set<string>>();
  const activeResourceTypes = new Set(allOperations.map((o) => o.resourceType));
  for (const rt of activeResourceTypes) {
    const filteredSet = new Set<string>(
      [...(fullDepsByResourceType.get(rt) ?? [])].filter((d) => activeResourceTypes.has(d)),
    );
    depsByResourceType.set(rt, filteredSet);
  }

  const executionOrder = computeTopologicalExecutionOrder(allOperations, depsByResourceType);
  const externalDependencies = [...externalDepsMap.values()];
  const executionGraph = buildExecutionDag(
    operationsMap,
    executionOrder,
    depsByResourceType,
    externalDependencies,
  );

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

  const effectiveSubscriptionId = options.subscriptionId ?? preSeededLedger?.subscriptionId;
  let providerLiveMetadata: ProviderLiveMetadata | undefined;
  if (
    options.checkLiveProvider &&
    effectiveSubscriptionId &&
    detectedNamespace !== "Unknown.Provider"
  ) {
    providerLiveMetadata = await fetchProviderLiveMetadata({
      armBaseUrl,
      armTokenResource,
      allowedArmOrigins,
      subscriptionId: effectiveSubscriptionId,
      providerNamespace: detectedNamespace,
      targetApiVersion: apiVersion,
      bearerToken: options.bearerToken,
    });
  }

  const now = new Date().toISOString();
  const ledger: CoverageLedger = {
    schemaVersion: "2.0-typespec",
    runId: preSeededLedger?.runId ?? crypto.randomBytes(4).toString("hex"),
    createdAt: preSeededLedger?.createdAt ?? now,
    updatedAt: now,
    serviceName,
    providerNamespace: detectedNamespace,
    apiVersion,
    availableApiVersions,
    typespecProjectDir,
    entrypointFile,
    subscriptionId: effectiveSubscriptionId,
    location:
      options.location ??
      preSeededLedger?.location ??
      preSeededLedger?.disposableResourceGroup?.location ??
      providerLiveMetadata?.recommendedLocations[0],
    armBaseUrl,
    armTokenResource,
    ...(allowedArmOrigins.length > 0 ? { allowedArmOrigins } : {}),
    ...(preSeededLedger?.disposableResourceGroup
      ? { disposableResourceGroup: preSeededLedger.disposableResourceGroup }
      : {}),
    providerLiveMetadata,
    externalDependencies,
    executionGraph,
    provisionedFixtures: preSeededLedger?.provisionedFixtures ?? [],
    runtimeState: preSeededLedger?.runtimeState ?? {
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

export function partitionLedgerIntoShards(options: {
  workDir: string;
  shardCount?: number;
  maxOpsPerShard?: number;
  outputDir?: string;
}): ShardPartitionManifest {
  const parentWorkDir = path.resolve(options.workDir);
  const parentLedger = loadLedger(parentWorkDir);
  const allOps = Object.values(parentLedger.operations);
  if (allOps.length === 0) {
    throw new Error(`Parent ledger in "${parentWorkDir}" has 0 discovered operations.`);
  }

  const maxOps = Math.max(10, options.maxOpsPerShard ?? 140);
  const targetShardCount = Math.max(
    1,
    Math.min(allOps.length, options.shardCount ?? Math.ceil(allOps.length / maxOps)),
  );
  const shardsBaseDir = path.resolve(options.outputDir ?? path.join(parentWorkDir, "shards"));
  fs.rmSync(shardsBaseDir, { recursive: true, force: true });
  fs.mkdirSync(shardsBaseDir, { recursive: true });

  // Group operations by root resource family (e.g. Microsoft.Network/virtualNetworks groups VNet + Subnets + Peerings)
  // while keeping oversized families splittable by exact resourceType if needed.
  const opsByResourceType = new Map<string, OperationContract[]>();
  const globalPreflightOps: OperationContract[] = [];
  for (const op of allOps) {
    if (op.phase === "preflight-discovery" && op.depth === 0) {
      globalPreflightOps.push(op);
      continue;
    }
    const bucket = opsByResourceType.get(op.resourceType) ?? [];
    bucket.push(op);
    opsByResourceType.set(op.resourceType, bucket);
  }

  // Group resourceTypes by top-level collection (Microsoft.Foo/<topCollection>) unless that family > maxOps * 1.25.
  const familyBuckets = new Map<string, string[]>();
  for (const rt of opsByResourceType.keys()) {
    const segs = rt.split("/");
    const rootKey = segs.length >= 2 ? `${segs[0]}/${segs[1]}` : rt;
    const list = familyBuckets.get(rootKey) ?? [];
    list.push(rt);
    familyBuckets.set(rootKey, list);
  }

  const units: Array<{ key: string; resourceTypes: string[]; opCount: number }> = [];
  for (const [familyKey, rts] of familyBuckets.entries()) {
    const totalCount = rts.reduce((acc, rt) => acc + (opsByResourceType.get(rt)?.length ?? 0), 0);
    if (totalCount <= Math.ceil(maxOps * 1.25) || rts.length === 1) {
      units.push({ key: familyKey, resourceTypes: rts.sort(), opCount: totalCount });
    } else {
      for (const rt of rts.sort()) {
        units.push({
          key: rt,
          resourceTypes: [rt],
          opCount: opsByResourceType.get(rt)?.length ?? 0,
        });
      }
    }
  }

  // Greedy LPT bin-packing (largest unit first into lightest shard) for balanced shard sizes.
  units.sort((a, b) => b.opCount - a.opCount || a.key.localeCompare(b.key));
  const shardBins: Array<{
    primaryResourceTypes: Set<string>;
    primaryOps: Set<string>;
    load: number;
  }> = Array.from({ length: targetShardCount }, () => ({
    primaryResourceTypes: new Set<string>(),
    primaryOps: new Set<string>(),
    load: 0,
  }));

  // Assign global depth-0 preflight ops to Shard 0.
  for (const preOp of globalPreflightOps) {
    shardBins[0].primaryOps.add(preOp.operationId);
    shardBins[0].primaryResourceTypes.add(preOp.resourceType);
    shardBins[0].load += 1;
  }

  for (const unit of units) {
    let minIdx = 0;
    for (let i = 1; i < shardBins.length; i++) {
      if (shardBins[i].load < shardBins[minIdx].load) {
        minIdx = i;
      }
    }
    for (const rt of unit.resourceTypes) {
      shardBins[minIdx].primaryResourceTypes.add(rt);
      for (const op of opsByResourceType.get(rt) ?? []) {
        shardBins[minIdx].primaryOps.add(op.operationId);
      }
    }
    shardBins[minIdx].load += unit.opCount;
  }

  // Build resource dependency map from parentledger.operations (parent-child + intraRpDependencies).
  const depsByRt = new Map<string, Set<string>>();
  const creatableByLower = new Map<string, string>();
  for (const op of allOps) {
    if (op.phase === "create" && op.depth >= 1) {
      creatableByLower.set(op.resourceType.toLowerCase(), op.resourceType);
    }
  }
  for (const op of allOps) {
    if (!depsByRt.has(op.resourceType)) {
      depsByRt.set(op.resourceType, new Set());
    }
    const parts = op.resourceType.split("/");
    if (parts.length >= 3) {
      const parentRt = creatableByLower.get(parts.slice(0, -1).join("/").toLowerCase());
      if (parentRt && parentRt !== op.resourceType) {
        depsByRt.get(op.resourceType)!.add(parentRt);
      }
    }
    for (const intra of op.intraRpDependencies ?? []) {
      depsByRt.get(op.resourceType)!.add(intra);
    }
  }

  const nonEmptyBins = shardBins.filter((b) => b.primaryOps.size > 0);
  const manifestShards: ShardPartitionManifest["shards"] = [];
  const now = new Date().toISOString();

  nonEmptyBins.forEach((bin, idx) => {
    const shardId = `shard-${String(idx + 1).padStart(2, "0")}`;
    const shardWorkDir = path.join(shardsBaseDir, shardId);
    fs.mkdirSync(shardWorkDir, { recursive: true });

    // Close over transitive prerequisite resourceTypes so this shard can create/delete parents/refs in its own RG.
    const prereqTypes = new Set<string>();
    const queue = [...bin.primaryResourceTypes];
    while (queue.length > 0) {
      const cur = queue.shift()!;
      for (const depRt of depsByRt.get(cur) ?? []) {
        if (!bin.primaryResourceTypes.has(depRt) && !prereqTypes.has(depRt)) {
          prereqTypes.add(depRt);
          queue.push(depRt);
        }
      }
    }

    const shardOperationsMap: Record<string, OperationContract> = {};
    for (const op of allOps) {
      const include =
        bin.primaryOps.has(op.operationId) ||
        (prereqTypes.has(op.resourceType) && (op.phase === "create" || op.phase === "delete"));
      if (include) {
        shardOperationsMap[op.operationId] = op;
      }
    }

    const shardOpsList = Object.values(shardOperationsMap);
    const shardDepsByRt = new Map<string, Set<string>>();
    const shardRtSet = new Set(shardOpsList.map((o) => o.resourceType));
    for (const rt of shardRtSet) {
      shardDepsByRt.set(
        rt,
        new Set([...(depsByRt.get(rt) ?? [])].filter((d) => shardRtSet.has(d))),
      );
    }
    const shardExecOrder = computeTopologicalExecutionOrder(shardOpsList, shardDepsByRt);
    const shardExtDepsMap = new Map<string, ExternalDependencyHint>();
    for (const op of shardOpsList) {
      for (const d of op.externalDependencies) {
        const k = `${d.kind}:${d.providerNamespace ?? ""}:${d.propertyPath}`;
        if (!shardExtDepsMap.has(k)) shardExtDepsMap.set(k, d);
      }
    }
    const shardExtDeps = [...shardExtDepsMap.values()];
    const shardDag = buildExecutionDag(
      shardOperationsMap,
      shardExecOrder,
      shardDepsByRt,
      shardExtDeps,
    );

    const shardCoverage: Record<string, OperationCoverageEntry> = {};
    for (const opId of shardExecOrder) {
      const c = shardOperationsMap[opId];
      const isPrimary = bin.primaryOps.has(opId);
      shardCoverage[opId] = {
        operationId: opId,
        method: c.method,
        pathTemplate: c.pathTemplate,
        sourceLocation: c.sourceLocation,
        phase: c.phase,
        resourceType: c.resourceType,
        status: isPrimary ? "pending" : "skipped",
        ...(isPrimary
          ? {}
          : {
              blockerReason:
                "Prerequisite helper contract (primary coverage owned by sibling shard)",
            }),
        attempts: 0,
        traceFiles: [],
        discrepancyCount: 0,
        generatedExamples: [],
      };
    }

    const shardLedger: CoverageLedger = {
      schemaVersion: "2.0-typespec",
      runId: `${parentLedger.runId}-${shardId}`,
      createdAt: now,
      updatedAt: now,
      serviceName: parentLedger.serviceName,
      providerNamespace: parentLedger.providerNamespace,
      apiVersion: parentLedger.apiVersion,
      availableApiVersions: parentLedger.availableApiVersions,
      typespecProjectDir: parentLedger.typespecProjectDir,
      entrypointFile: parentLedger.entrypointFile,
      subscriptionId: parentLedger.subscriptionId,
      location: parentLedger.location,
      armBaseUrl: parentLedger.armBaseUrl,
      armTokenResource: parentLedger.armTokenResource,
      ...(parentLedger.allowedArmOrigins
        ? { allowedArmOrigins: parentLedger.allowedArmOrigins }
        : {}),
      ...(parentLedger.providerLiveMetadata
        ? { providerLiveMetadata: parentLedger.providerLiveMetadata }
        : {}),
      externalDependencies: shardExtDeps,
      executionGraph: shardDag,
      provisionedFixtures: [],
      runtimeState: {
        pathSlotValues: {},
        putBodiesByResourceType: {},
        listItemNamesByResourceType: {},
      },
      executionOrder: shardExecOrder,
      operations: shardOperationsMap,
      coverage: shardCoverage,
    };

    saveLedger(shardWorkDir, shardLedger);
    manifestShards.push({
      shardId,
      workDir: shardWorkDir,
      primaryOperationCount: bin.primaryOps.size,
      totalOperationCount: shardExecOrder.length,
      resourceTypes: [...bin.primaryResourceTypes].sort(),
      prerequisiteResourceTypes: [...prereqTypes].sort(),
    });
  });

  const manifest: ShardPartitionManifest = {
    schemaVersion: "1.0",
    createdAt: now,
    parentWorkDir,
    serviceName: parentLedger.serviceName,
    providerNamespace: parentLedger.providerNamespace,
    apiVersion: parentLedger.apiVersion,
    totalOperations: allOps.length,
    shardCount: manifestShards.length,
    shards: manifestShards,
  };
  fs.writeFileSync(
    path.join(parentWorkDir, "shard-manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
  return manifest;
}
