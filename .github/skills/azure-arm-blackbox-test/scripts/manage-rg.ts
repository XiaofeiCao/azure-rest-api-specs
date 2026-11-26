import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import {
  extractProvisioningState,
  isFailedOrCanceledState,
  isNonTerminalProvisioningState,
} from "./analyze-behavior.ts";
import {
  DISPOSABLE_RG_PREFIX,
  getActiveAzSubscriptionId,
  getArmBearerToken,
  inferArmTokenResource,
  isValidDisposableRgName,
  parseRetryAfterMs,
  resolveArmRelativeOrAbsoluteUrl,
  RUN_OWNERSHIP_TAG,
  sendRawHttpExchange,
  validateAndNormalizeAllowedArmOrigins,
  validateAndNormalizeArmBaseUrl,
  verifyLiveDisposableRgOwnership,
} from "./auth-and-http.ts";
import { getLedgerPath, loadLedger, saveLedger, updateLedgerAtomically } from "./ledger-store.ts";
import type { CoverageLedger, ExternalDependencyKind, ProvisionedFixture } from "./types.ts";

const ARM_RESOURCES_API_VERSION = "2024-03-01";

export function generateDisposableRgName(serviceHint?: string): string {
  const cleanHint = (serviceHint ?? "svc")
    .toLowerCase()
    .replace(/^microsoft\./, "")
    .replace(/[^a-z0-9]/g, "")
    .slice(0, 12);
  const rand = crypto.randomBytes(3).toString("hex");
  return `${DISPOSABLE_RG_PREFIX}${cleanHint || "svc"}-${rand}`;
}

export async function createDisposableResourceGroup(options: {
  workDir: string;
  subscriptionId?: string;
  location?: string;
  rgName?: string;
  serviceHint?: string;
  armBaseUrl?: string;
  armTokenResource?: string;
  allowedArmOrigins?: string[];
  bearerToken?: string;
}): Promise<{ rgName: string; location: string; subscriptionId: string }> {
  let ledger: CoverageLedger;
  if (fs.existsSync(getLedgerPath(options.workDir))) {
    ledger = loadLedger(options.workDir);
  } else {
    const initialArmBaseUrl = validateAndNormalizeArmBaseUrl(options.armBaseUrl);
    const isLoopbackBase = new URL(initialArmBaseUrl).protocol === "http:";
    const initialAllowedOrigins = validateAndNormalizeAllowedArmOrigins(
      options.allowedArmOrigins,
      isLoopbackBase,
    );
    const initialTokenResource = inferArmTokenResource(initialArmBaseUrl, options.armTokenResource);
    const now = new Date().toISOString();
    const fallbackHint = options.serviceHint ?? (path.basename(options.workDir) || "svc");
    ledger = {
      schemaVersion: "2.0-typespec",
      runId: crypto.randomBytes(4).toString("hex"),
      createdAt: now,
      updatedAt: now,
      serviceName: fallbackHint,
      providerNamespace: "",
      apiVersion: "",
      availableApiVersions: [],
      typespecProjectDir: "",
      entrypointFile: "",
      subscriptionId: options.subscriptionId,
      location: options.location,
      armBaseUrl: initialArmBaseUrl,
      armTokenResource: initialTokenResource,
      ...(initialAllowedOrigins.length > 0 ? { allowedArmOrigins: initialAllowedOrigins } : {}),
      externalDependencies: [],
      provisionedFixtures: [],
      executionOrder: [],
      operations: {},
      coverage: {},
    };
  }

  const activeExistingRg =
    ledger.disposableResourceGroup &&
    ledger.disposableResourceGroup.cleanupStatus !== "deleted" &&
    ledger.disposableResourceGroup.cleanupStatus !== "not_created"
      ? ledger.disposableResourceGroup
      : undefined;

  if (activeExistingRg) {
    if (options.rgName && options.rgName.toLowerCase() !== activeExistingRg.name.toLowerCase()) {
      throw new Error(
        `Cannot switch disposable Resource Group from "${activeExistingRg.name}" to "${options.rgName}" while cleanupStatus is "${activeExistingRg.cleanupStatus}"; delete the active group first.`,
      );
    }
    if (
      options.subscriptionId &&
      ledger.subscriptionId &&
      options.subscriptionId.toLowerCase() !== ledger.subscriptionId.toLowerCase()
    ) {
      throw new Error(
        `Cannot switch subscriptionId from "${ledger.subscriptionId}" to "${options.subscriptionId}" while disposable Resource Group "${activeExistingRg.name}" has cleanupStatus "${activeExistingRg.cleanupStatus}".`,
      );
    }
    if (options.armBaseUrl) {
      const normalizedNewBase = validateAndNormalizeArmBaseUrl(options.armBaseUrl);
      if (normalizedNewBase.toLowerCase() !== ledger.armBaseUrl.toLowerCase()) {
        throw new Error(
          `Cannot switch armBaseUrl from "${ledger.armBaseUrl}" to "${normalizedNewBase}" while disposable Resource Group "${activeExistingRg.name}" has cleanupStatus "${activeExistingRg.cleanupStatus}".`,
        );
      }
    }
  } else if (options.armBaseUrl) {
    ledger.armBaseUrl = validateAndNormalizeArmBaseUrl(options.armBaseUrl);
    if (!options.armTokenResource) {
      ledger.armTokenResource = inferArmTokenResource(ledger.armBaseUrl, undefined);
    }
  }

  if (options.armTokenResource) {
    ledger.armTokenResource = inferArmTokenResource(ledger.armBaseUrl, options.armTokenResource);
  }
  if (options.allowedArmOrigins) {
    const isLoopback = new URL(ledger.armBaseUrl).protocol === "http:";
    const validatedOrigins = validateAndNormalizeAllowedArmOrigins(
      options.allowedArmOrigins,
      isLoopback,
    );
    ledger.allowedArmOrigins = validatedOrigins.length > 0 ? validatedOrigins : undefined;
  }

  const subscriptionId =
    options.subscriptionId ?? ledger.subscriptionId ?? getActiveAzSubscriptionId();
  const location = options.location ?? ledger.location ?? "eastus";
  const rgName =
    options.rgName ??
    ledger.disposableResourceGroup?.name ??
    generateDisposableRgName(options.serviceHint ?? ledger.serviceName);

  if (!isValidDisposableRgName(rgName)) {
    throw new Error(
      `Disposable Resource Group name "${rgName}" must match "${DISPOSABLE_RG_PREFIX}<alphanumeric>".`,
    );
  }

  const token = getArmBearerToken({
    explicitToken: options.bearerToken,
    subscriptionId,
    armBaseUrl: ledger.armBaseUrl,
    tokenResource: ledger.armTokenResource,
  });

  const runId = ledger.runId ?? crypto.randomBytes(4).toString("hex");
  ledger.runId = runId;

  const url = resolveArmRelativeOrAbsoluteUrl(
    ledger.armBaseUrl,
    `/subscriptions/${encodeURIComponent(subscriptionId)}/resourcegroups/${encodeURIComponent(rgName)}?api-version=${ARM_RESOURCES_API_VERSION}`,
  );
  const safetyContext = {
    trustedArmBaseUrl: ledger.armBaseUrl,
    allowedArmOrigins: ledger.allowedArmOrigins,
    subscriptionId,
    disposableRgName: rgName,
    allowDisposableRgLifecycle: true,
  };

  // Check whether a Resource Group with this name already exists; refuse reuse unless its per-run ownership tag matches!
  const existingCheck = await sendRawHttpExchange({
    step: "initial",
    method: "GET",
    url,
    bearerToken: token,
    safetyContext,
  });
  if (existingCheck.response.status >= 200 && existingCheck.response.status < 300) {
    const existingBody =
      existingCheck.response.body && typeof existingCheck.response.body === "object"
        ? (existingCheck.response.body as Record<string, unknown>)
        : undefined;
    const existingTags =
      existingBody?.tags && typeof existingBody.tags === "object"
        ? (existingBody.tags as Record<string, unknown>)
        : undefined;
    const existingOwnerRunId =
      typeof existingTags?.[RUN_OWNERSHIP_TAG] === "string"
        ? existingTags[RUN_OWNERSHIP_TAG]
        : undefined;
    if (existingOwnerRunId !== runId) {
      throw new Error(
        `Refusing to reuse existing Resource Group "${rgName}": ${RUN_OWNERSHIP_TAG} tag is "${existingOwnerRunId ?? "<missing>"}", expected "${runId}".`,
      );
    }
  } else if (existingCheck.response.status !== 404) {
    throw new Error(
      `Failed to verify Resource Group "${rgName}" ownership before creation: HTTP ${existingCheck.response.status}`,
    );
  }

  // Persist cleanup target BEFORE sending the mutating PUT so interrupted runs can still tear down safely.
  if (
    ledger.subscriptionId &&
    ledger.subscriptionId.toLowerCase() !== subscriptionId.toLowerCase()
  ) {
    ledger.provisionedFixtures = [];
    ledger.runtimeState = undefined;
  }
  const createdAt = ledger.disposableResourceGroup?.createdAt ?? new Date().toISOString();
  ledger.subscriptionId = subscriptionId;
  ledger.location = location;
  ledger.disposableResourceGroup = {
    name: rgName,
    location,
    runId,
    createdAt,
    cleanupStatus: "creating",
  };
  saveLedger(options.workDir, ledger);

  const exchange = await sendRawHttpExchange({
    step: "initial",
    method: "PUT",
    url,
    bearerToken: token,
    body: {
      location,
      tags: {
        purpose: "arm-spec-blackbox-test",
        [RUN_OWNERSHIP_TAG]: runId,
        service: ledger.providerNamespace,
        apiVersion: ledger.apiVersion,
        createdAt,
      },
    },
    safetyContext,
  });

  if (exchange.response.status < 200 || exchange.response.status >= 300) {
    ledger.disposableResourceGroup.cleanupStatus = "cleanup_failed";
    saveLedger(options.workDir, ledger);
    throw new Error(
      `Failed to create disposable Resource Group "${rgName}": HTTP ${exchange.response.status} ${JSON.stringify(exchange.response.body ?? "")}`,
    );
  }

  ledger.disposableResourceGroup.cleanupStatus = "active";
  saveLedger(options.workDir, ledger);

  return { rgName, location, subscriptionId };
}

export async function deleteDisposableResourceGroup(options: {
  workDir: string;
  wait?: boolean;
  pollIntervalMs?: number;
  maxPollAttempts?: number;
  bearerToken?: string;
}): Promise<{ rgName: string; cleanupStatus: "deleting" | "deleted" }> {
  const ledger = loadLedger(options.workDir);
  const rg = ledger.disposableResourceGroup;
  if (!rg || !ledger.subscriptionId) {
    throw new Error("No active disposable Resource Group recorded in coverage ledger.");
  }

  const token = getArmBearerToken({
    explicitToken: options.bearerToken,
    subscriptionId: ledger.subscriptionId,
    armBaseUrl: ledger.armBaseUrl,
    tokenResource: ledger.armTokenResource,
  });
  const url = resolveArmRelativeOrAbsoluteUrl(
    ledger.armBaseUrl,
    `/subscriptions/${encodeURIComponent(ledger.subscriptionId)}/resourcegroups/${encodeURIComponent(rg.name)}?api-version=${ARM_RESOURCES_API_VERSION}`,
  );
  const safetyContext = {
    trustedArmBaseUrl: ledger.armBaseUrl,
    allowedArmOrigins: ledger.allowedArmOrigins,
    subscriptionId: ledger.subscriptionId,
    disposableRgName: rg.name,
    allowDisposableRgLifecycle: true,
  };

  const expectedRunId = rg.runId ?? ledger.runId;
  const preDeleteGet = await sendRawHttpExchange({
    step: "initial",
    method: "GET",
    url,
    bearerToken: token,
    safetyContext,
  });
  if (preDeleteGet.response.status === 404) {
    rg.cleanupStatus = "deleted";
    rg.deletedAt = new Date().toISOString();
    saveLedger(options.workDir, ledger);
    return { rgName: rg.name, cleanupStatus: "deleted" };
  }
  if (preDeleteGet.response.status >= 200 && preDeleteGet.response.status < 300) {
    const existingBody =
      preDeleteGet.response.body && typeof preDeleteGet.response.body === "object"
        ? (preDeleteGet.response.body as Record<string, unknown>)
        : undefined;
    const existingTags =
      existingBody?.tags && typeof existingBody.tags === "object"
        ? (existingBody.tags as Record<string, unknown>)
        : undefined;
    const actualRunId =
      typeof existingTags?.[RUN_OWNERSHIP_TAG] === "string"
        ? existingTags[RUN_OWNERSHIP_TAG]
        : undefined;
    if (!expectedRunId || actualRunId !== expectedRunId) {
      throw new Error(
        `Blocked deletion of Resource Group "${rg.name}": ${RUN_OWNERSHIP_TAG} tag is "${actualRunId ?? "<missing>"}", expected "${expectedRunId ?? "<unrecorded>"}".`,
      );
    }
  } else {
    throw new Error(
      `Failed to verify Resource Group "${rg.name}" ownership before deletion: HTTP ${preDeleteGet.response.status}`,
    );
  }

  const delExchange = await sendRawHttpExchange({
    step: "initial",
    method: "DELETE",
    url,
    bearerToken: token,
    safetyContext,
  });

  if (
    delExchange.response.status !== 200 &&
    delExchange.response.status !== 202 &&
    delExchange.response.status !== 204 &&
    delExchange.response.status !== 404
  ) {
    rg.cleanupStatus = "cleanup_failed";
    saveLedger(options.workDir, ledger);
    throw new Error(
      `Failed to delete disposable Resource Group "${rg.name}": HTTP ${delExchange.response.status} ${JSON.stringify(delExchange.response.body ?? "")}`,
    );
  }

  if (
    delExchange.response.status === 200 ||
    delExchange.response.status === 204 ||
    delExchange.response.status === 404
  ) {
    rg.cleanupStatus = "deleted";
    rg.deletedAt = new Date().toISOString();
    saveLedger(options.workDir, ledger);
    return { rgName: rg.name, cleanupStatus: "deleted" };
  }

  rg.cleanupStatus = "deleting";
  saveLedger(options.workDir, ledger);

  if (options.wait) {
    const pollIntervalMs = options.pollIntervalMs ?? 5000;
    const maxAttempts = options.maxPollAttempts ?? Number.POSITIVE_INFINITY;
    for (let i = 0; i < maxAttempts; i++) {
      await delay(pollIntervalMs);
      const refreshedToken = getArmBearerToken({
        explicitToken: options.bearerToken,
        subscriptionId: ledger.subscriptionId,
        armBaseUrl: ledger.armBaseUrl,
        tokenResource: ledger.armTokenResource,
      });
      const check = await sendRawHttpExchange({
        step: "poll",
        method: "GET",
        url,
        bearerToken: refreshedToken,
        safetyContext: {
          trustedArmBaseUrl: ledger.armBaseUrl,
          allowedArmOrigins: ledger.allowedArmOrigins,
          subscriptionId: ledger.subscriptionId,
          disposableRgName: rg.name,
          allowDisposableRgLifecycle: true,
        },
      });
      if (check.response.status === 404) {
        rg.cleanupStatus = "deleted";
        rg.deletedAt = new Date().toISOString();
        saveLedger(options.workDir, ledger);
        return { rgName: rg.name, cleanupStatus: "deleted" };
      }
    }
  }

  return { rgName: rg.name, cleanupStatus: rg.cleanupStatus };
}

async function putArmFixtureAndWait(options: {
  armBaseUrl: string;
  allowedArmOrigins?: string[];
  subscriptionId: string;
  resourcePathWithQuery: string;
  body: unknown;
  bearerToken: string;
  refreshBearerToken?: () => string;
  disposableRgName: string;
  disposableRgCleanupStatus: string;
  expectedRunId: string;
  verifiedRgRunIdTag: string;
  pollIntervalMs?: number;
  maxPollAttempts?: number;
}): Promise<Record<string, unknown>> {
  const url = resolveArmRelativeOrAbsoluteUrl(options.armBaseUrl, options.resourcePathWithQuery);
  const safetyContext = {
    trustedArmBaseUrl: options.armBaseUrl,
    allowedArmOrigins: options.allowedArmOrigins,
    subscriptionId: options.subscriptionId,
    disposableRgName: options.disposableRgName,
    disposableRgCleanupStatus: options.disposableRgCleanupStatus,
    expectedRunId: options.expectedRunId,
    verifiedRgRunIdTag: options.verifiedRgRunIdTag,
    allowDisposableRgLifecycle: false,
  };

  const initial = await sendRawHttpExchange({
    step: "initial",
    method: "PUT",
    url,
    bearerToken: options.bearerToken,
    body: options.body,
    safetyContext,
  });

  if (initial.response.status < 200 || initial.response.status >= 300) {
    throw new Error(
      `Fixture PUT failed (${options.resourcePathWithQuery}): HTTP ${initial.response.status} ${JSON.stringify(initial.response.body ?? "")}`,
    );
  }

  const asyncHeader =
    initial.response.headers["azure-asyncoperation"] ??
    initial.response.headers["operation-location"] ??
    initial.response.headers.location;
  const initialProvState = extractProvisioningState(initial.response.body);
  const isAlreadyTerminal200 =
    initial.response.status === 200 &&
    initialProvState !== undefined &&
    !isNonTerminalProvisioningState(initialProvState);
  const needsPoll =
    !isAlreadyTerminal200 &&
    (Boolean(asyncHeader) ||
      initial.response.status === 202 ||
      isNonTerminalProvisioningState(initialProvState));

  const pollIntervalMs = options.pollIntervalMs ?? 3000;
  const maxAttempts = options.maxPollAttempts ?? Number.POSITIVE_INFINITY;

  if (needsPoll) {
    const pollUrl = asyncHeader
      ? resolveArmRelativeOrAbsoluteUrl(options.armBaseUrl, asyncHeader)
      : url;
    let lastWaitHeaders = initial.response.headers;
    let pollCompleted = false;

    for (let i = 0; i < maxAttempts; i++) {
      const waitMs = parseRetryAfterMs(lastWaitHeaders, pollIntervalMs);
      if (waitMs > 0) {
        await delay(waitMs);
      }
      const activeToken = options.refreshBearerToken
        ? options.refreshBearerToken()
        : options.bearerToken;
      const poll = await sendRawHttpExchange({
        step: "poll",
        method: "GET",
        url: pollUrl,
        bearerToken: activeToken,
        safetyContext,
      });
      lastWaitHeaders = poll.response.headers;
      if (poll.response.status === 429) {
        continue;
      }
      if (poll.response.status < 200 || poll.response.status >= 300) {
        throw new Error(
          `Fixture LRO poll failed (${options.resourcePathWithQuery}): HTTP ${poll.response.status} ${JSON.stringify(poll.response.body ?? "")}`,
        );
      }

      const rec =
        poll.response.body && typeof poll.response.body === "object"
          ? (poll.response.body as Record<string, unknown>)
          : {};
      const status =
        typeof rec.status === "string"
          ? rec.status.trim().toLowerCase()
          : extractProvisioningState(poll.response.body)?.toLowerCase();

      if (isFailedOrCanceledState(status)) {
        throw new Error(
          `Fixture LRO failed (${options.resourcePathWithQuery}): ${JSON.stringify(poll.response.body ?? "")}`,
        );
      }
      if (
        status === "succeeded" ||
        (!asyncHeader && poll.response.status === 200 && !isNonTerminalProvisioningState(status)) ||
        (Boolean(initial.response.headers.location) &&
          !initial.response.headers["azure-asyncoperation"] &&
          poll.response.status !== 202 &&
          !isNonTerminalProvisioningState(status))
      ) {
        pollCompleted = true;
        break;
      }
    }

    if (!pollCompleted) {
      throw new Error(
        `Fixture LRO timed out after ${maxAttempts} poll attempts (${options.resourcePathWithQuery}).`,
      );
    }
  }

  const finalGet = await sendRawHttpExchange({
    step: "final-get",
    method: "GET",
    url,
    bearerToken: options.bearerToken,
    safetyContext,
  });
  if (finalGet.response.status < 200 || finalGet.response.status >= 300) {
    throw new Error(
      `Fixture final GET failed (${options.resourcePathWithQuery}): HTTP ${finalGet.response.status} ${JSON.stringify(finalGet.response.body ?? "")}`,
    );
  }
  const finalProv = extractProvisioningState(finalGet.response.body);
  if (isNonTerminalProvisioningState(finalProv) || isFailedOrCanceledState(finalProv)) {
    throw new Error(
      `Fixture final GET returned non-ready provisioningState "${finalProv}" (${options.resourcePathWithQuery}).`,
    );
  }
  if (!finalGet.response.body || typeof finalGet.response.body !== "object") {
    throw new Error(
      `Fixture final GET returned an empty or non-JSON resource body (${options.resourcePathWithQuery}).`,
    );
  }
  return finalGet.response.body as Record<string, unknown>;
}

/**
 * Built-in external cross-RP setup fixture provisioner inside the disposable RG.
 */
export async function provisionExternalFixture(options: {
  workDir: string;
  kind: ExternalDependencyKind;
  name?: string;
  targetPrivateLinkResourceId?: string;
  groupIds?: string[];
  customResourcePath?: string;
  customApiVersion?: string;
  customBody?: Record<string, unknown>;
  pollIntervalMs?: number;
  maxPollAttempts?: number;
  bearerToken?: string;
}): Promise<ProvisionedFixture> {
  const ledger = loadLedger(options.workDir);
  if (!ledger.subscriptionId || !ledger.disposableResourceGroup) {
    throw new Error(
      "Create the disposable Resource Group (`rg create`) before provisioning external fixtures.",
    );
  }
  if (ledger.disposableResourceGroup.cleanupStatus !== "active") {
    throw new Error(
      `Refusing to provision fixture while disposable Resource Group "${ledger.disposableResourceGroup.name}" has cleanupStatus "${ledger.disposableResourceGroup.cleanupStatus}".`,
    );
  }
  const expectedRunId = ledger.disposableResourceGroup.runId ?? ledger.runId;
  if (!expectedRunId) {
    throw new Error(
      `Refusing to provision fixture in Resource Group "${ledger.disposableResourceGroup.name}": missing recorded runId ownership marker.`,
    );
  }

  const sub = ledger.subscriptionId;
  const rg = ledger.disposableResourceGroup.name;
  const location = ledger.disposableResourceGroup.location;
  const rand = crypto.randomBytes(3).toString("hex");
  const token = getArmBearerToken({
    explicitToken: options.bearerToken,
    subscriptionId: sub,
    armBaseUrl: ledger.armBaseUrl,
    tokenResource: ledger.armTokenResource,
  });
  const verifiedRgRunIdTag = await verifyLiveDisposableRgOwnership({
    armBaseUrl: ledger.armBaseUrl,
    allowedArmOrigins: ledger.allowedArmOrigins,
    subscriptionId: sub,
    rgName: rg,
    expectedRunId,
    bearerToken: token,
  });

  const rgPrefix = `/subscriptions/${encodeURIComponent(sub)}/resourceGroups/${encodeURIComponent(rg)}`;
  let fixture: ProvisionedFixture;

  if (options.kind === "managed-identity") {
    const name = options.name ?? `bbx-uami-${rand}`;
    const resourcePath = `${rgPrefix}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${encodeURIComponent(name)}`;
    const body = await putArmFixtureAndWait({
      armBaseUrl: ledger.armBaseUrl,
      allowedArmOrigins: ledger.allowedArmOrigins,
      subscriptionId: sub,
      resourcePathWithQuery: `${resourcePath}?api-version=2023-01-31`,
      body: { location },
      bearerToken: token,
      disposableRgName: rg,
      disposableRgCleanupStatus: ledger.disposableResourceGroup.cleanupStatus,
      expectedRunId,
      verifiedRgRunIdTag,
      pollIntervalMs: options.pollIntervalMs,
      maxPollAttempts: options.maxPollAttempts,
    });
    fixture = {
      kind: "managed-identity",
      name,
      resourceId: typeof body.id === "string" ? body.id : resourcePath,
      provisionedAt: new Date().toISOString(),
      metadata: {
        principalId: (body.properties as Record<string, unknown> | undefined)?.principalId,
        clientId: (body.properties as Record<string, unknown> | undefined)?.clientId,
      },
    };
  } else if (options.kind === "vnet-subnet") {
    const name = options.name ?? `bbx-vnet-${rand}`;
    const resourcePath = `${rgPrefix}/providers/Microsoft.Network/virtualNetworks/${encodeURIComponent(name)}`;
    const body = await putArmFixtureAndWait({
      armBaseUrl: ledger.armBaseUrl,
      allowedArmOrigins: ledger.allowedArmOrigins,
      subscriptionId: sub,
      resourcePathWithQuery: `${resourcePath}?api-version=2023-11-01`,
      body: {
        location,
        properties: {
          addressSpace: { addressPrefixes: ["10.42.0.0/16"] },
          subnets: [
            {
              name: "default",
              properties: {
                addressPrefix: "10.42.1.0/24",
                privateEndpointNetworkPolicies: "Disabled",
              },
            },
          ],
        },
      },
      bearerToken: token,
      disposableRgName: rg,
      disposableRgCleanupStatus: ledger.disposableResourceGroup.cleanupStatus,
      expectedRunId,
      verifiedRgRunIdTag,
      pollIntervalMs: options.pollIntervalMs,
    });
    const vnetId = typeof body.id === "string" ? body.id : resourcePath;
    fixture = {
      kind: "vnet-subnet",
      name,
      resourceId: vnetId,
      provisionedAt: new Date().toISOString(),
      metadata: {
        subnetId: `${vnetId}/subnets/default`,
      },
    };
  } else if (options.kind === "private-endpoint") {
    if (!options.targetPrivateLinkResourceId || !options.groupIds?.length) {
      throw new Error(
        "private-endpoint fixture requires --target-resource-id and --group-ids (e.g. configurationStores).",
      );
    }
    const cleanTargetId = options.targetPrivateLinkResourceId.trim().replace(/\/+$/, "");
    const targetIdMatch =
      /^\/subscriptions\/([^/]+)\/resourcegroups\/([^/]+)\/providers\/.+$/i.exec(cleanTargetId);
    if (
      !targetIdMatch ||
      targetIdMatch[1].toLowerCase() !== sub.toLowerCase() ||
      targetIdMatch[2].toLowerCase() !== rg.toLowerCase()
    ) {
      throw new Error(
        `Blocked private-endpoint fixture targeting "${options.targetPrivateLinkResourceId}": target resource must reside inside subscription "${sub}" and disposable Resource Group "${rg}".`,
      );
    }
    const isRecordedTarget = ledger.provisionedFixtures.some(
      (f) => f.resourceId.replace(/\/+$/, "").toLowerCase() === cleanTargetId.toLowerCase(),
    );
    if (!isRecordedTarget) {
      throw new Error(
        `Blocked private-endpoint fixture targeting "${options.targetPrivateLinkResourceId}": target resource is not recorded in provisionedFixtures for this run.`,
      );
    }
    let vnetFixture = ledger.provisionedFixtures.find((f) => f.kind === "vnet-subnet");
    if (!vnetFixture) {
      vnetFixture = await provisionExternalFixture({
        workDir: options.workDir,
        kind: "vnet-subnet",
        pollIntervalMs: options.pollIntervalMs,
        bearerToken: options.bearerToken,
      });
      // Reload ledger after recursive save.
    }
    const freshLedger = loadLedger(options.workDir);
    const subnetId =
      typeof vnetFixture.metadata?.subnetId === "string"
        ? vnetFixture.metadata.subnetId
        : `${vnetFixture.resourceId}/subnets/default`;
    const name = options.name ?? `bbx-pe-${rand}`;
    const resourcePath = `${rgPrefix}/providers/Microsoft.Network/privateEndpoints/${encodeURIComponent(name)}`;
    const body = await putArmFixtureAndWait({
      armBaseUrl: freshLedger.armBaseUrl,
      allowedArmOrigins: freshLedger.allowedArmOrigins,
      subscriptionId: sub,
      resourcePathWithQuery: `${resourcePath}?api-version=2023-11-01`,
      body: {
        location,
        properties: {
          subnet: { id: subnetId },
          privateLinkServiceConnections: [
            {
              name: `${name}-conn`,
              properties: {
                privateLinkServiceId: options.targetPrivateLinkResourceId,
                groupIds: options.groupIds,
              },
            },
          ],
        },
      },
      bearerToken: token,
      disposableRgName: rg,
      disposableRgCleanupStatus: freshLedger.disposableResourceGroup?.cleanupStatus ?? "active",
      expectedRunId,
      verifiedRgRunIdTag,
      pollIntervalMs: options.pollIntervalMs,
    });
    fixture = {
      kind: "private-endpoint",
      name,
      resourceId: typeof body.id === "string" ? body.id : resourcePath,
      provisionedAt: new Date().toISOString(),
      metadata: { subnetId, targetPrivateLinkResourceId: options.targetPrivateLinkResourceId },
    };
    updateLedgerAtomically(options.workDir, (locked) => {
      locked.provisionedFixtures.push(fixture);
    });
    return fixture;
  } else if (options.kind === "storage-account") {
    const name = (options.name ?? `bbxst${rand}${crypto.randomBytes(2).toString("hex")}`)
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "")
      .slice(0, 24);
    const resourcePath = `${rgPrefix}/providers/Microsoft.Storage/storageAccounts/${encodeURIComponent(name)}`;
    const body = await putArmFixtureAndWait({
      armBaseUrl: ledger.armBaseUrl,
      allowedArmOrigins: ledger.allowedArmOrigins,
      subscriptionId: sub,
      resourcePathWithQuery: `${resourcePath}?api-version=2023-05-01`,
      body: {
        location,
        sku: { name: "Standard_LRS" },
        kind: "StorageV2",
        properties: {
          minimumTlsVersion: "TLS1_2",
          allowBlobPublicAccess: false,
        },
      },
      bearerToken: token,
      disposableRgName: rg,
      disposableRgCleanupStatus: ledger.disposableResourceGroup.cleanupStatus,
      expectedRunId,
      verifiedRgRunIdTag,
      pollIntervalMs: options.pollIntervalMs,
    });
    fixture = {
      kind: "storage-account",
      name,
      resourceId: typeof body.id === "string" ? body.id : resourcePath,
      provisionedAt: new Date().toISOString(),
    };
  } else if (options.kind === "log-analytics") {
    const name = options.name ?? `bbx-law-${rand}`;
    const resourcePath = `${rgPrefix}/providers/Microsoft.OperationalInsights/workspaces/${encodeURIComponent(name)}`;
    const body = await putArmFixtureAndWait({
      armBaseUrl: ledger.armBaseUrl,
      allowedArmOrigins: ledger.allowedArmOrigins,
      subscriptionId: sub,
      resourcePathWithQuery: `${resourcePath}?api-version=2023-09-01`,
      body: {
        location,
        properties: { sku: { name: "PerGB2018" }, retentionInDays: 30 },
      },
      bearerToken: token,
      disposableRgName: rg,
      disposableRgCleanupStatus: ledger.disposableResourceGroup.cleanupStatus,
      expectedRunId,
      verifiedRgRunIdTag,
      pollIntervalMs: options.pollIntervalMs,
    });
    fixture = {
      kind: "log-analytics",
      name,
      resourceId: typeof body.id === "string" ? body.id : resourcePath,
      provisionedAt: new Date().toISOString(),
    };
  } else if (
    options.kind === "custom" ||
    options.kind === "generic-arm-resource" ||
    options.kind === "key-vault"
  ) {
    if (!options.customResourcePath || !options.customApiVersion) {
      throw new Error(
        `Fixture kind "${options.kind}" requires --resource-path (e.g. "providers/Microsoft.KeyVault/vaults/mykv") and --api-version.`,
      );
    }
    const cleanRelOrAbs = options.customResourcePath
      .trim()
      .replace(/\?.*$/, "")
      .replace(/\/+$/, "");
    let fullResourcePath: string;
    if (/^\/?providers\/[^/]+\/.+/i.test(cleanRelOrAbs)) {
      fullResourcePath = `${rgPrefix}/${cleanRelOrAbs.replace(/^\/+/, "")}`;
    } else if (/^\/subscriptions\//i.test(cleanRelOrAbs)) {
      const m = /^\/subscriptions\/([^/]+)\/resourcegroups\/([^/]+)\/(providers\/.+)$/i.exec(
        cleanRelOrAbs,
      );
      if (
        !m ||
        m[1].toLowerCase() !== sub.toLowerCase() ||
        m[2].toLowerCase() !== rg.toLowerCase()
      ) {
        throw new Error(
          `Blocked custom fixture "${options.customResourcePath}": must reside inside subscription "${sub}" and disposable Resource Group "${rg}".`,
        );
      }
      fullResourcePath = `${rgPrefix}/${m[3]}`;
    } else {
      throw new Error(
        `Invalid --resource-path "${options.customResourcePath}": expected "providers/<Namespace>/<type>/<name>" or full path inside disposable RG "${rg}".`,
      );
    }
    const refreshBearerToken = () =>
      getArmBearerToken({
        explicitToken: options.bearerToken,
        subscriptionId: sub,
        armBaseUrl: ledger.armBaseUrl,
        tokenResource: ledger.armTokenResource,
      });
    const effectiveBody =
      options.customBody && typeof options.customBody === "object"
        ? "location" in options.customBody
          ? options.customBody
          : { location, ...options.customBody }
        : { location, properties: {} };
    const body = await putArmFixtureAndWait({
      armBaseUrl: ledger.armBaseUrl,
      allowedArmOrigins: ledger.allowedArmOrigins,
      subscriptionId: sub,
      resourcePathWithQuery: `${fullResourcePath}?api-version=${encodeURIComponent(options.customApiVersion.trim())}`,
      body: effectiveBody,
      bearerToken: token,
      refreshBearerToken,
      disposableRgName: rg,
      disposableRgCleanupStatus: ledger.disposableResourceGroup.cleanupStatus,
      expectedRunId,
      verifiedRgRunIdTag,
      pollIntervalMs: options.pollIntervalMs,
      maxPollAttempts: options.maxPollAttempts,
    });
    const derivedName = options.name ?? fullResourcePath.split("/").pop() ?? `bbx-custom-${rand}`;
    fixture = {
      kind: options.kind,
      name: derivedName,
      resourceId: typeof body.id === "string" ? body.id : fullResourcePath,
      provisionedAt: new Date().toISOString(),
    };
  } else {
    throw new Error(
      `Unsupported external fixture kind "${String(options.kind)}". Use --kind custom --resource-path "providers/<RP>/<type>/<name>" --api-version <ver> --body-json '<json>'.`,
    );
  }

  updateLedgerAtomically(options.workDir, (locked) => {
    locked.provisionedFixtures.push(fixture);
  });
  return fixture;
}
