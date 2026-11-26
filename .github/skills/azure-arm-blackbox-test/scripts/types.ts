export type ArmOperationScope = "tenant" | "subscription" | "resourceGroup" | "extension";

export type HttpMethod = "GET" | "PUT" | "PATCH" | "POST" | "DELETE" | "HEAD" | "OPTIONS";

export type LifecyclePhase =
  | "preflight-discovery"
  | "external-fixture"
  | "negative-precheck"
  | "create"
  | "read"
  | "list"
  | "update"
  | "action"
  | "delete"
  | "deleted-resource";

export type ExternalDependencyKind =
  | "managed-identity"
  | "vnet-subnet"
  | "private-endpoint"
  | "key-vault"
  | "storage-account"
  | "log-analytics"
  | "generic-arm-resource"
  | "custom";

export interface TypeSpecSourceLocation {
  file: string;
  line: number;
  column: number;
}

export interface ExternalDependencyHint {
  propertyPath: string;
  providerNamespace?: string;
  kind: ExternalDependencyKind;
  required: boolean;
  description?: string;
}

export interface OperationParameterSpec {
  name: string;
  in: "path" | "query" | "header" | "body";
  required: boolean;
  type?: string;
  format?: string;
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  allowReserved?: boolean;
  enumValues?: string[];
  mutability?: string[];
  readOnly?: boolean;
  secretCandidate?: boolean;
  externalResourceReference?: ExternalDependencyKind;
}

export interface PageableContract {
  nextLinkName?: string | null;
  itemName: string;
}

export interface SecretStringConstraint {
  minLength?: number;
  maxLength?: number;
  pattern?: string;
}

export interface SecretCycleRule {
  basePath: string;
  repeatPath: string;
}

export interface OperationContract {
  operationId: string;
  method: HttpMethod;
  pathTemplate: string;
  typespecProjectDir: string;
  entrypointFile: string;
  sourceLocation?: TypeSpecSourceLocation;
  apiVersion: string;
  scope: ArmOperationScope;
  resourceType: string;
  depth: number;
  phase: LifecyclePhase;
  declaredStatusCodes: string[];
  declaredResponseHeaders: Record<string, string[]>;
  declaredRequiredResponseHeaders?: Record<string, string[][]>;
  declaredResponseHasSchema: Record<string, boolean>;
  isLroDeclared: boolean;
  lroFinalStateVia?: string;
  pageable?: PageableContract;
  inferredPagination?: PageableContract;
  hasDefaultErrorResponse: boolean;
  parameters: OperationParameterSpec[];
  writableBodyProperties: string[];
  readOnlyBodyProperties: string[];
  secretProperties: string[];
  secretCycleRules?: SecretCycleRule[];
  secretConstraints?: Record<string, SecretStringConstraint>;
  secretResponseHeaders?: string[];
  secretResponseStatuses?: string[];
  intraRpDependencies?: string[];
  externalDependencies: ExternalDependencyHint[];
  existingExampleNames: string[];
  existingExamplePaths: string[];
}

export interface ProviderResourceTypeMetadata {
  resourceType: string;
  apiVersions: string[];
  defaultApiVersion?: string;
  locations: string[];
}

export interface ProviderLiveMetadata {
  namespace: string;
  registrationState?: string;
  resourceTypes: ProviderResourceTypeMetadata[];
  targetVersionSupportedOnArm: boolean;
  recommendedLocations: string[];
}

export type OperationCoverageStatus =
  | "pending"
  | "passed"
  | "passed_with_mismatch"
  | "failed_service_error"
  | "blocked"
  | "skipped";

export interface OperationCoverageEntry {
  operationId: string;
  method: HttpMethod;
  pathTemplate: string;
  sourceLocation?: TypeSpecSourceLocation;
  phase: LifecyclePhase;
  resourceType: string;
  status: OperationCoverageStatus;
  attempts: number;
  traceFiles: string[];
  discrepancyCount: number;
  generatedExamples: string[];
  blockerReason?: string;
  lastHttpStatus?: number;
}

export interface DisposableResourceGroupState {
  name: string;
  location: string;
  runId?: string;
  createdAt?: string;
  deletedAt?: string;
  cleanupStatus: "not_created" | "creating" | "active" | "deleting" | "deleted" | "cleanup_failed";
}

export interface OwnedTargetResource {
  subscriptionId?: string;
  providerNamespace: string;
  collectionSegment: string;
  name: string;
  location?: string;
  resourceGroupName?: string;
  resourceId: string;
}

export interface ProvisionedFixture {
  kind: ExternalDependencyKind | "target-rp-resource";
  name: string;
  resourceId: string;
  provisionedAt: string;
  metadata?: Record<string, unknown>;
}

export interface LedgerRuntimeState {
  pathSlotValues: Record<string, string>;
  putBodiesByResourceType: Record<string, Record<string, unknown>>;
  listItemNamesByResourceType: Record<string, string[]>;
}

export interface ExecutionDagNode {
  id: string;
  kind: "operation" | "external-fixture";
  operationId?: string;
  fixtureKind?: ExternalDependencyKind;
  resourceType?: string;
  phase: LifecyclePhase;
  topoTier: number;
}

export interface ExecutionDagEdge {
  from: string;
  to: string;
  reason:
    | "preflight-before-create"
    | "external-fixture-prereq"
    | "parent-before-child"
    | "intra-rp-resource-ref"
    | "create-before-lifecycle"
    | "lifecycle-before-delete"
    | "child-delete-before-parent-delete"
    | "dependent-delete-before-prereq-delete"
    | "delete-before-soft-delete-purge";
}

export interface ExecutionDag {
  nodes: ExecutionDagNode[];
  edges: ExecutionDagEdge[];
}

export interface ShardPartitionEntry {
  shardId: string;
  workDir: string;
  primaryOperationCount: number;
  totalOperationCount: number;
  resourceTypes: string[];
  prerequisiteResourceTypes: string[];
}

export interface ShardPartitionManifest {
  schemaVersion: "1.0";
  createdAt: string;
  parentWorkDir: string;
  serviceName: string;
  providerNamespace: string;
  apiVersion: string;
  totalOperations: number;
  shardCount: number;
  shards: ShardPartitionEntry[];
}

export interface CoverageLedger {
  schemaVersion: "2.0-typespec";
  runId?: string;
  createdAt: string;
  updatedAt: string;
  serviceName: string;
  providerNamespace: string;
  apiVersion: string;
  availableApiVersions: string[];
  typespecProjectDir: string;
  entrypointFile: string;
  subscriptionId?: string;
  location?: string;
  armBaseUrl: string;
  armTokenResource?: string;
  allowedArmOrigins?: string[];
  disposableResourceGroup?: DisposableResourceGroupState;
  mergedShardResourceGroups?: DisposableResourceGroupState[];
  providerLiveMetadata?: ProviderLiveMetadata;
  externalDependencies: ExternalDependencyHint[];
  provisionedFixtures: ProvisionedFixture[];
  runtimeState?: LedgerRuntimeState;
  executionGraph?: ExecutionDag;
  executionOrder: string[];
  operations: Record<string, OperationContract>;
  coverage: Record<string, OperationCoverageEntry>;
}

export type ExchangeStep = "initial" | "poll" | "final-get" | "next-page";

export interface WireHttpExchange {
  step: ExchangeStep;
  timestamp: string;
  durationMs: number;
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: unknown;
  };
  response: {
    status: number;
    headers: Record<string, string>;
    body?: unknown;
    rawTextSnippet?: string;
  };
}

export const DISCREPANCY_RULES = {
  LRO_UNDECLARED: "LRO-UNDECLARED",
  LRO_HEADER_DRIFT: "LRO-HEADER-DRIFT",
  LRO_FINAL_STATE_DRIFT: "LRO-FINAL-STATE-DRIFT",
  STATUS_CODE_DRIFT: "STATUS-CODE-DRIFT",
  SCHEMA_RESPONSE_DRIFT: "SCHEMA-RESPONSE-DRIFT",
  SCHEMA_REQUEST_REJECTED: "SCHEMA-REQUEST-REJECTED",
  ROUNDTRIP_MUTABILITY_DRIFT: "ROUNDTRIP-MUTABILITY-DRIFT",
  PAGEABLE_CONTRACT_DRIFT: "PAGEABLE-CONTRACT-DRIFT",
  ERROR_ENVELOPE_DRIFT: "ERROR-ENVELOPE-DRIFT",
  PROVISIONING_STATE_DRIFT: "PROVISIONING-STATE-DRIFT",
} as const;

export type DiscrepancyRuleId = (typeof DISCREPANCY_RULES)[keyof typeof DISCREPANCY_RULES];

export type DiscrepancySeverity = "blocking" | "warning" | "info";

export interface BehavioralDiscrepancy {
  ruleId: DiscrepancyRuleId;
  severity: DiscrepancySeverity;
  operationId: string;
  sourceLocation?: TypeSpecSourceLocation;
  summary: string;
  specExpectation: string;
  actualWireBehavior: string;
  evidence: Record<string, unknown>;
}

export interface TypeSpecSchemaIssue {
  code: string;
  message: string;
  path: string;
  severity: "error" | "warning";
}

export interface ObservedLroBehavior {
  detected: boolean;
  detectionSignals: string[];
  pollCount: number;
  completionStatus?: "not-applicable" | "succeeded" | "failed" | "timed_out";
  terminalProvisioningState?: string;
  pollingHeaderUsed?: "azure-asyncoperation" | "location" | "operation-location" | "resource-get";
  finalResultSource?:
    | "initial-body"
    | "status-monitor-body"
    | "location-body"
    | "final-resource-get"
    | "none";
}

export interface ProbeRequestInput {
  operationId: string;
  scenario?: string;
  expectError?: boolean;
  method?: HttpMethod;
  pathOrUrl?: string;
  pathParams?: Record<string, string>;
  query?: Record<string, string>;
  headers?: Record<string, string>;
  body?: unknown;
  priorPutBody?: unknown;
  followNextLink?: boolean;
  maxPaginationPages?: number;
  pollLro?: boolean;
  maxPollAttempts?: number;
  maxPollDurationMs?: number;
  pollIntervalMs?: number;
}

export interface ProbeTrace {
  sequence: number;
  operationId: string;
  scenario: string;
  expectError: boolean;
  probeSucceeded?: boolean;
  failureReason?: string;
  typespecProjectDir: string;
  sourceLocation?: TypeSpecSourceLocation;
  apiVersion: string;
  observedLro: ObservedLroBehavior;
  exchanges: WireHttpExchange[];
  requestSchemaErrors: TypeSpecSchemaIssue[];
  responseSchemaErrors: TypeSpecSchemaIssue[];
  discrepancies: BehavioralDiscrepancy[];
}

export interface GeneratedExampleArtifact {
  operationId: string;
  scenario: string;
  exampleName: string;
  scratchPath: string;
  writtenSpecPaths: string[];
  schemaValid: boolean;
  schemaErrors: string[];
  observedStatusCodes: string[];
  missingDeclaredStatusCodes: string[];
  oavComplete: boolean;
  oavIssues: string[];
  specWriteSkippedReason?: string;
}
