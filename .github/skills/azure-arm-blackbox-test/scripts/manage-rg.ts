import * as crypto from "node:crypto";
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
  isValidDisposableRgName,
  sendRawHttpExchange,
} from "./auth-and-http.ts";
import { loadLedger, saveLedger } from "./ledger-store.ts";
import type { ExternalDependencyKind, ProvisionedFixture } from "./types.ts";

const ARM_RESOURCES_API_VERSION = "2024-03-01";
const RUN_OWNERSHIP_TAG = "arm-blackbox-run-id";

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
  bearerToken?: string;
}): Promise<{ rgName: string; location: string; subscriptionId: string }> {
  const ledger = loadLedger(options.workDir);
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
  }

  const subscriptionId =
    options.subscriptionId ?? ledger.subscriptionId ?? getActiveAzSubscriptionId();
  const location = options.location ?? ledger.location ?? "eastus";
  const rgName =
    options.rgName ??
    ledger.disposableResourceGroup?.name ??
    generateDisposableRgName(ledger.serviceName);

  if (!isValidDisposableRgName(rgName)) {
    throw new Error(
      `Disposable Resource Group name "${rgName}" must match "${DISPOSABLE_RG_PREFIX}<alphanumeric>".`,
    );
  }

  const token = getArmBearerToken({
    explicitToken: options.bearerToken,
    subscriptionId,
  });

  const runId = ledger.runId ?? crypto.randomBytes(4).toString("hex");
  ledger.runId = runId;

  const base = ledger.armBaseUrl.replace(/\/+$/, "");
  const url = `${base}/subscriptions/${encodeURIComponent(subscriptionId)}/resourcegroups/${encodeURIComponent(rgName)}?api-version=${ARM_RESOURCES_API_VERSION}`;
  const safetyContext = {
    trustedArmBaseUrl: ledger.armBaseUrl,
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
  });
  const base = ledger.armBaseUrl.replace(/\/+$/, "");
  const url = `${base}/subscriptions/${encodeURIComponent(ledger.subscriptionId)}/resourcegroups/${encodeURIComponent(rg.name)}?api-version=${ARM_RESOURCES_API_VERSION}`;
  const safetyContext = {
    trustedArmBaseUrl: ledger.armBaseUrl,
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
    const maxAttempts = options.maxPollAttempts ?? 60;
    for (let i = 0; i < maxAttempts; i++) {
      await delay(pollIntervalMs);
      const check = await sendRawHttpExchange({
        step: "poll",
        method: "GET",
        url,
        bearerToken: token,
        safetyContext: {
          trustedArmBaseUrl: ledger.armBaseUrl,
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
  subscriptionId: string;
  resourcePathWithQuery: string;
  body: unknown;
  bearerToken: string;
  disposableRgName: string;
  pollIntervalMs?: number;
  maxPollAttempts?: number;
}): Promise<Record<string, unknown>> {
  const base = options.armBaseUrl.replace(/\/+$/, "");
  const url = `${base}${options.resourcePathWithQuery}`;
  const safetyContext = {
    trustedArmBaseUrl: options.armBaseUrl,
    subscriptionId: options.subscriptionId,
    disposableRgName: options.disposableRgName,
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
  const needsPoll =
    Boolean(asyncHeader) ||
    initial.response.status === 202 ||
    isNonTerminalProvisioningState(initialProvState);

  const pollIntervalMs = options.pollIntervalMs ?? 3000;
  const maxAttempts = options.maxPollAttempts ?? 40;

  if (needsPoll) {
    const pollUrl = asyncHeader
      ? /^https?:\/\//i.test(asyncHeader)
        ? asyncHeader
        : `${base}${asyncHeader.startsWith("/") ? "" : "/"}${asyncHeader}`
      : url;
    let pollCompleted = false;

    for (let i = 0; i < maxAttempts; i++) {
      await delay(pollIntervalMs);
      const poll = await sendRawHttpExchange({
        step: "poll",
        method: "GET",
        url: pollUrl,
        bearerToken: options.bearerToken,
        safetyContext,
      });
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
  pollIntervalMs?: number;
  bearerToken?: string;
}): Promise<ProvisionedFixture> {
  const ledger = loadLedger(options.workDir);
  if (!ledger.subscriptionId || !ledger.disposableResourceGroup) {
    throw new Error(
      "Create the disposable Resource Group (`rg create`) before provisioning external fixtures.",
    );
  }

  const sub = ledger.subscriptionId;
  const rg = ledger.disposableResourceGroup.name;
  const location = ledger.disposableResourceGroup.location;
  const rand = crypto.randomBytes(3).toString("hex");
  const token = getArmBearerToken({
    explicitToken: options.bearerToken,
    subscriptionId: sub,
  });

  const rgPrefix = `/subscriptions/${encodeURIComponent(sub)}/resourceGroups/${encodeURIComponent(rg)}`;
  let fixture: ProvisionedFixture;

  if (options.kind === "managed-identity") {
    const name = options.name ?? `bbx-uami-${rand}`;
    const resourcePath = `${rgPrefix}/providers/Microsoft.ManagedIdentity/userAssignedIdentities/${encodeURIComponent(name)}`;
    const body = await putArmFixtureAndWait({
      armBaseUrl: ledger.armBaseUrl,
      subscriptionId: sub,
      resourcePathWithQuery: `${resourcePath}?api-version=2023-01-31`,
      body: { location },
      bearerToken: token,
      disposableRgName: rg,
      pollIntervalMs: options.pollIntervalMs,
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
      pollIntervalMs: options.pollIntervalMs,
    });
    fixture = {
      kind: "private-endpoint",
      name,
      resourceId: typeof body.id === "string" ? body.id : resourcePath,
      provisionedAt: new Date().toISOString(),
      metadata: { subnetId, targetPrivateLinkResourceId: options.targetPrivateLinkResourceId },
    };
    freshLedger.provisionedFixtures.push(fixture);
    saveLedger(options.workDir, freshLedger);
    return fixture;
  } else if (options.kind === "storage-account") {
    const name = (options.name ?? `bbxst${rand}${crypto.randomBytes(2).toString("hex")}`)
      .toLowerCase()
      .replace(/[^a-z0-9]/g, "")
      .slice(0, 24);
    const resourcePath = `${rgPrefix}/providers/Microsoft.Storage/storageAccounts/${encodeURIComponent(name)}`;
    const body = await putArmFixtureAndWait({
      armBaseUrl: ledger.armBaseUrl,
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
      subscriptionId: sub,
      resourcePathWithQuery: `${resourcePath}?api-version=2023-09-01`,
      body: {
        location,
        properties: { sku: { name: "PerGB2018" }, retentionInDays: 30 },
      },
      bearerToken: token,
      disposableRgName: rg,
      pollIntervalMs: options.pollIntervalMs,
    });
    fixture = {
      kind: "log-analytics",
      name,
      resourceId: typeof body.id === "string" ? body.id : resourcePath,
      provisionedAt: new Date().toISOString(),
    };
  } else {
    throw new Error(
      `Unsupported automatic external fixture kind "${options.kind}". Provision custom cross-RP fixtures using raw ARM PUT inside "${rg}".`,
    );
  }

  ledger.provisionedFixtures.push(fixture);
  saveLedger(options.workDir, ledger);
  return fixture;
}
