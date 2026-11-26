import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  analyzeBehavioralDiscrepancies,
  runTypeSpecLiveValidation,
} from "../scripts/analyze-behavior.ts";
import {
  assertSafeArmTarget,
  assertTrustedArmOrigin,
  inferArmTokenResource,
  stripConfiguredArmBasePath,
  validateAndNormalizeArmBaseUrl,
} from "../scripts/auth-and-http.ts";
import { runCli } from "../scripts/cli.ts";
import { executeOperationProbe, executeProbeBatch } from "../scripts/execute-probe.ts";
import {
  evaluateExampleOavCompleteness,
  generateLiveExamples,
} from "../scripts/generate-examples.ts";
import { mergeShardWorkDirs, updateLedgerAtomically } from "../scripts/ledger-store.ts";
import {
  createDisposableResourceGroup,
  deleteDisposableResourceGroup,
  provisionExternalFixture,
} from "../scripts/manage-rg.ts";
import { discoverSpecInventory, partitionLedgerIntoShards } from "../scripts/plan-inventory.ts";
import { buildSummaryReport } from "../scripts/render-report.ts";
import { sanitizePayload } from "../scripts/sanitize-example.ts";
import {
  DISCREPANCY_RULES,
  type CoverageLedger,
  type OperationContract,
} from "../scripts/types.ts";

const REAL_SUB_ID = "87654321-4321-4321-4321-210987654321";
const MOCK_TOKEN = "mock-bearer-token-value";

function ledgerRawSnapshotForContract(workDir: string, operationId: string): OperationContract {
  const ledger = JSON.parse(
    fs.readFileSync(path.join(workDir, "coverage-ledger.json"), "utf8"),
  ) as CoverageLedger;
  const found = ledger.operations[operationId];
  if (!found) {
    throw new Error(`Missing operation ${operationId}`);
  }
  return found;
}

function createMinimalArmMockTypeSpecProject(dir: string): string {
  const projectDir = path.join(dir, "MockWidget.Management");
  fs.mkdirSync(projectDir, { recursive: true });
  fs.writeFileSync(path.join(projectDir, "tspconfig.yaml"), "{}\n", "utf8");

  const mainTsp = `
import "@typespec/http";
import "@typespec/rest";
import "@typespec/versioning";
import "@typespec/openapi";
import "@azure-tools/typespec-azure-core";
import "@azure-tools/typespec-azure-resource-manager";

using TypeSpec.Http;
using TypeSpec.Rest;
using TypeSpec.Versioning;
using TypeSpec.OpenAPI;
using Azure.Core;
using Azure.ResourceManager;

@armProviderNamespace
@service(#{ title: "MockWidgetManagementClient" })
@versioned(Versions)
@armCommonTypesVersion(Azure.ResourceManager.CommonTypes.Versions.v5)
namespace Microsoft.MockWidget;

enum Versions {
  v2025_01_01: "2025-01-01",
}

union WidgetProvisioningState {
  string,
  Creating: "Creating",
  Succeeded: "Succeeded",
  Failed: "Failed",
  Canceled: "Canceled",
}

union ExportFormat {
  string,
  Json: "Json",
  Csv: "Csv",
}

model WidgetProperties {
  skuTier?: string;
  droppedField?: string;
  exportFormat?: ExportFormat;
  @visibility(Lifecycle.Read)
  provisioningState?: WidgetProvisioningState;
}

model Widget is TrackedResource<WidgetProperties> {
  ...ResourceNameParameter<Widget>;
}

model ExportResult {
  downloadUrl?: string;
}

model WidgetKeys {
  @secret
  primaryKey?: string;
  connectionString?: string;
}

@armResourceOperations
interface Widgets {
  @operationId("Widgets_Get")
  get is ArmResourceRead<Widget>;

  @operationId("Widgets_CreateOrUpdate")
  createOrUpdate is ArmResourceCreateOrReplaceAsync<Widget>;

  @operationId("Widgets_ListByResourceGroup")
  listByResourceGroup is ArmResourceListByParent<Widget>;

  // Intentionally modeled as synchronous to test LRO-UNDECLARED detection!
  @operationId("Widgets_Restart")
  restart is ArmResourceActionSync<Widget, void, OkResponse>;

  // Defaults to ArmLroLocationHeader (final-state-via = location) to test LRO-FINAL-STATE-DRIFT!
  @operationId("Widgets_Export")
  export is ArmResourceActionAsync<Widget, void, ExportResult>;

  @operationId("Widgets_ListKeys")
  listKeys is ArmResourceActionSync<Widget, void, WidgetKeys>;
}
`;

  fs.writeFileSync(path.join(projectDir, "main.tsp"), `${mainTsp.trim()}\n`, "utf8");
  return projectDir;
}

describe("azure-arm-blackbox-test TypeSpec-native harness", () => {
  const tempDirs: string[] = [];
  const servers: http.Server[] = [];
  const localWorkRoot = path.join(import.meta.dirname, "..", ".work");

  function makeTempDir(): string {
    fs.mkdirSync(localWorkRoot, { recursive: true });
    const dir = path.join(localWorkRoot, `test-${crypto.randomBytes(4).toString("hex")}`);
    fs.mkdirSync(dir, { recursive: true });
    tempDirs.push(dir);
    return dir;
  }

  afterEach(async () => {
    for (const srv of servers.splice(0)) {
      await new Promise<void>((resolve) => srv.close(() => resolve()));
    }
    for (const dir of tempDirs.splice(0)) {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("enforces origin, subscription, ownership, and disposable Resource Group guardrails strictly", () => {
    const ctx = {
      trustedArmBaseUrl: "https://management.azure.com",
      subscriptionId: REAL_SUB_ID,
      disposableRgName: "rg-arm-blackbox-appconfig-abc123",
      ownedTargetResources: [
        {
          providerNamespace: "Microsoft.AppConfiguration",
          collectionSegment: "configurationStores",
          name: "bbx-store-01",
          location: "eastus",
          resourceGroupName: "rg-arm-blackbox-appconfig-abc123",
          resourceId: `/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-arm-blackbox-appconfig-abc123/providers/Microsoft.AppConfiguration/configurationStores/bbx-store-01`,
        },
      ],
      allowDisposableRgLifecycle: false,
    };

    // Read-only calls on the trusted ARM HTTPS origin are permitted.
    expect(() =>
      assertSafeArmTarget(
        "GET",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-prod/providers/Microsoft.AppConfiguration/configurationStores?api-version=2024-06-01`,
        ctx,
      ),
    ).not.toThrow();

    // Off-origin GETs (e.g. malicious Location / nextLink) and plaintext HTTP are blocked before attaching Bearer token (#4)!
    expect(() =>
      assertSafeArmTarget("GET", "https://attacker.example.com/nextLink?page=2", ctx),
    ).toThrow(/untrusted origin/);
    expect(() =>
      assertSafeArmTarget(
        "GET",
        `http://management.azure.com/subscriptions/${REAL_SUB_ID}/providers/Microsoft.AppConfiguration/operations`,
        ctx,
      ),
    ).toThrow(/untrusted origin|HTTPS is required/);

    // Non-destructive checkNameAvailability POST is permitted on matching subscription.
    expect(() =>
      assertSafeArmTarget(
        "POST",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/providers/Microsoft.AppConfiguration/checkNameAvailability?api-version=2024-06-01`,
        ctx,
      ),
    ).not.toThrow();

    // Mutations inside the disposable RG and matching subscription are permitted.
    expect(() =>
      assertSafeArmTarget(
        "PUT",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-arm-blackbox-appconfig-abc123/providers/Microsoft.AppConfiguration/configurationStores/bbx-store-01?api-version=2024-06-01`,
        ctx,
      ),
    ).not.toThrow();

    // Cross-subscription DELETE with the same disposable RG name is blocked (#2)!
    expect(() =>
      assertSafeArmTarget(
        "DELETE",
        "https://management.azure.com/subscriptions/00000000-9999-9999-9999-999999999999/resourceGroups/rg-arm-blackbox-appconfig-abc123/providers/Microsoft.AppConfiguration/configurationStores/bbx-store-01?api-version=2024-06-01",
        ctx,
      ),
    ).toThrow(/strictly confined to subscription/);

    // Soft-delete purge of a recorded ownedResourceNames entry is permitted, while unrecorded "bbx-production" is blocked (#3)!
    expect(() =>
      assertSafeArmTarget(
        "POST",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/providers/Microsoft.AppConfiguration/locations/eastus/deletedConfigurationStores/bbx-store-01/purge?api-version=2024-06-01`,
        ctx,
      ),
    ).not.toThrow();

    expect(() =>
      assertSafeArmTarget(
        "POST",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/providers/Microsoft.AppConfiguration/locations/eastus/deletedConfigurationStores/bbx-production/purge?api-version=2024-06-01`,
        ctx,
      ),
    ).toThrow(/no matching target-RP resource identity/);

    // Same resource name under a different RP or location is ALSO blocked (#7821)!
    expect(() =>
      assertSafeArmTarget(
        "POST",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/providers/Microsoft.KeyVault/locations/eastus/deletedVaults/bbx-store-01/purge?api-version=2024-06-01`,
        ctx,
      ),
    ).toThrow(/no matching target-RP resource identity/);
    expect(() =>
      assertSafeArmTarget(
        "POST",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/providers/Microsoft.AppConfiguration/locations/westus2/deletedConfigurationStores/bbx-store-01/purge?api-version=2024-06-01`,
        ctx,
      ),
    ).toThrow(/no matching target-RP resource identity/);

    expect(() =>
      assertSafeArmTarget(
        "POST",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/providers/Microsoft.AppConfiguration/locations/eastus/deletedConfigurationStores/customer-prod-store/purge?api-version=2024-06-01`,
        ctx,
      ),
    ).toThrow(/Blocked (?:mutating|soft-delete) POST/);

    // Cross-scope RG moveResources, external targetResourceGroup, and external privateLinkServiceId are blocked (#3904, #7656)!
    expect(() =>
      assertSafeArmTarget(
        "POST",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-arm-blackbox-appconfig-abc123/moveResources?api-version=2024-03-01`,
        ctx,
        {
          targetResourceGroup: `/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-production`,
        },
      ),
    ).toThrow(/Blocked cross-scope|outside disposable Resource Group/);

    expect(() =>
      assertSafeArmTarget(
        "PUT",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-arm-blackbox-appconfig-abc123/providers/Microsoft.Network/privateEndpoints/pe1?api-version=2023-11-01`,
        ctx,
        {
          properties: {
            privateLinkServiceConnections: [
              {
                properties: {
                  privateLinkServiceId: `/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-production/providers/Microsoft.AppConfiguration/configurationStores/prodStore`,
                },
              },
            ],
          },
        },
      ),
    ).toThrow(/Blocked cross-scope/);

    // Mutations targeting another RG are blocked!
    expect(() =>
      assertSafeArmTarget(
        "DELETE",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-production/providers/Microsoft.AppConfiguration/configurationStores/prod?api-version=2024-06-01`,
        ctx,
      ),
    ).toThrow(/strictly confined/);
  });

  it("compiles multi-resource ARM TypeSpec in-memory and builds a parent-child-delete-purge DAG with .tsp:line provenance", async () => {
    const tempRoot = makeTempDir();
    const workDir = path.join(tempRoot, "work-dag");
    const repoRoot = path.resolve(import.meta.dirname, "../../../..");
    const realAppConfigSpec = path.join(
      repoRoot,
      "specification",
      "appconfiguration",
      "resource-manager",
      "Microsoft.AppConfiguration",
      "AppConfiguration",
    );

    // Support both full checkouts and CI sparse checkouts where `specification/` is excluded!
    let specPathToTest = realAppConfigSpec;
    const isUsingRealSpec = fs.existsSync(realAppConfigSpec);
    if (!isUsingRealSpec) {
      const synthDir = path.join(tempRoot, "SynthAppConfig");
      fs.mkdirSync(synthDir, { recursive: true });
      fs.writeFileSync(path.join(synthDir, "tspconfig.yaml"), "{}\n", "utf8");
      fs.writeFileSync(
        path.join(synthDir, "ConfigurationStore.tsp"),
        `
import "@typespec/http";
import "@typespec/rest";
import "@typespec/versioning";
import "@typespec/openapi";
import "@azure-tools/typespec-azure-core";
import "@azure-tools/typespec-azure-resource-manager";

using TypeSpec.Http;
using TypeSpec.Rest;
using TypeSpec.Versioning;
using TypeSpec.OpenAPI;
using Azure.Core;
using Azure.ResourceManager;

@armProviderNamespace
@service(#{ title: "AppConfigurationManagementClient" })
@versioned(Versions)
@armCommonTypesVersion(Azure.ResourceManager.CommonTypes.Versions.v5)
namespace Microsoft.AppConfiguration;

enum Versions {
  v2025_06_01_preview: "2025-06-01-preview",
}

model ConfigurationStoreProperties {
  disableLocalAuth?: boolean;
  @visibility(Lifecycle.Read)
  provisioningState?: ResourceProvisioningState;
}

model ConfigurationStore is TrackedResource<ConfigurationStoreProperties> {
  ...ResourceNameParameter<ConfigurationStore, "configStoreName", "configurationStores">;
}

@parentResource(ConfigurationStore)
model KeyValue is ProxyResource<{ value?: string }> {
  ...ResourceNameParameter<KeyValue, "keyValueName", "keyValues">;
}

@parentResource(ConfigurationStore)
model Replica is ProxyResource<{ provisioningState?: ResourceProvisioningState }> {
  ...ResourceNameParameter<Replica, "replicaName", "replicas">;
}

@subscriptionResource
@parentResource(SubscriptionLocationResource)
model DeletedConfigurationStore is ProxyResource<{ storeId?: string }> {
  ...ResourceNameParameter<DeletedConfigurationStore, "configStoreName", "deletedConfigurationStores">;
}

interface Operations extends Azure.ResourceManager.Operations {}

@armResourceOperations
interface ConfigurationStores {
  @operationId("ConfigurationStores_Get")
  get is ArmResourceRead<ConfigurationStore>;
  @operationId("ConfigurationStores_Create")
  create is ArmResourceCreateOrReplaceAsync<ConfigurationStore>;
  @operationId("ConfigurationStores_Delete")
  delete is ArmResourceDeleteWithoutOkAsync<ConfigurationStore>;
}

@armResourceOperations
interface KeyValues {
  @operationId("KeyValues_CreateOrUpdate")
  createOrUpdate is ArmResourceCreateOrReplaceSync<KeyValue>;
  @operationId("KeyValues_Delete")
  delete is ArmResourceDeleteSync<KeyValue>;
}

@armResourceOperations
interface Replicas {
  @operationId("Replicas_Create")
  create is ArmResourceCreateOrReplaceAsync<Replica>;
  @operationId("Replicas_ListByConfigurationStore")
  listByConfigurationStore is ArmResourceListByParent<Replica>;
}

@armResourceOperations
interface DeletedStores {
  @operationId("ConfigurationStores_PurgeDeleted")
  purgeDeleted is ArmResourceActionAsync<DeletedConfigurationStore, void, OkResponse>;
}
`.trim() + "\n",
        "utf8",
      );
      fs.writeFileSync(
        path.join(synthDir, "main.tsp"),
        'import "./ConfigurationStore.tsp";\n',
        "utf8",
      );
      specPathToTest = synthDir;
    }

    const ledger = await discoverSpecInventory({
      specPath: specPathToTest,
      apiVersion: "2025-06-01-preview",
      workDir,
    });

    expect(ledger.providerNamespace).toBe("Microsoft.AppConfiguration");
    expect(ledger.apiVersion).toBe("2025-06-01-preview");
    expect(ledger.availableApiVersions).toContain("2025-06-01-preview");
    expect(ledger.operations.ConfigurationStores_Create.sourceLocation?.file).toMatch(
      /ConfigurationStore\.tsp$/,
    );
    if (isUsingRealSpec) {
      expect(ledger.executionOrder.length).toBe(29);
    }

    const idxOpsList = ledger.executionOrder.indexOf("Operations_List");
    const idxStoreCreate = ledger.executionOrder.indexOf("ConfigurationStores_Create");
    const idxKeyValCreate = ledger.executionOrder.indexOf("KeyValues_CreateOrUpdate");
    const idxReplicaCreate = ledger.executionOrder.indexOf("Replicas_Create");
    const idxReplicaList = ledger.executionOrder.indexOf("Replicas_ListByConfigurationStore");
    const idxKeyValDelete = ledger.executionOrder.indexOf("KeyValues_Delete");
    const idxStoreDelete = ledger.executionOrder.indexOf("ConfigurationStores_Delete");
    const idxPurgeDeleted = ledger.executionOrder.indexOf("ConfigurationStores_PurgeDeleted");

    expect(idxOpsList).toBeGreaterThanOrEqual(0);
    expect(idxPurgeDeleted).toBeGreaterThanOrEqual(0);
    expect(idxOpsList).toBeLessThan(idxStoreCreate);
    expect(idxStoreCreate).toBeLessThan(idxKeyValCreate);
    // Child GET collection retains depth=2 and sorts AFTER child creation (#25)!
    expect(ledger.operations.Replicas_ListByConfigurationStore.depth).toBe(2);
    expect(idxReplicaCreate).toBeLessThan(idxReplicaList);
    // Resource GET inherits paired PUT writableBodyProperties for round-trip checks (#26/#27)!
    expect(ledger.operations.ConfigurationStores_Get.writableBodyProperties.length).toBeGreaterThan(
      0,
    );
    // Child DELETE runs BEFORE parent DELETE!
    expect(idxKeyValDelete).toBeLessThan(idxStoreDelete);
    // Soft-deleted purge runs AFTER parent DELETE!
    expect(idxStoreDelete).toBeLessThan(idxPurgeDeleted);
  });

  it("detects undeclared LRO, final-state-via drift, round-trip drops, error drift, and generates TypeSpec-validated sanitized examples", async () => {
    const tempRoot = makeTempDir();
    const tspProjectDir = createMinimalArmMockTypeSpecProject(tempRoot);
    const workDir = path.join(tempRoot, "work");

    let putPollCounter = 0;
    let restartPollCounter = 0;
    let baseUrl = "";
    const rgStore = new Map<string, Record<string, unknown>>();

    const server = http.createServer((req, res) => {
      const reqUrl = new URL(req.url ?? "/", baseUrl);
      const pathname = reqUrl.pathname;
      const method = req.method?.toUpperCase() ?? "GET";

      // Disposable RG GET / PUT / DELETE with per-run ownership tags (#7890).
      if (
        /^\/subscriptions\/[^/]+\/resourcegroups\/rg-arm-blackbox-/i.test(pathname) &&
        !pathname.includes("/providers/")
      ) {
        const key = pathname.toLowerCase();
        if (method === "GET") {
          const existing = rgStore.get(key);
          if (!existing) {
            res.writeHead(404, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({ error: { code: "ResourceGroupNotFound", message: "Not found" } }),
            );
          } else {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(existing));
          }
          return;
        }
        if (method === "PUT") {
          const chunks: Buffer[] = [];
          req.on("data", (c: Buffer) => chunks.push(c));
          req.on("end", () => {
            const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as Record<
              string,
              unknown
            >;
            const record = { id: pathname, location: "eastus", ...parsed };
            rgStore.set(key, record);
            res.writeHead(201, { "Content-Type": "application/json" });
            res.end(JSON.stringify(record));
          });
          return;
        }
        if (method === "DELETE") {
          rgStore.delete(key);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ id: pathname }));
          return;
        }
      }

      // Async status monitor for Widget PUT.
      if (pathname.endsWith("/operationStatuses/op-put-1")) {
        putPollCounter++;
        const status = putPollCounter >= 2 ? "Succeeded" : "InProgress";
        res.writeHead(200, { "Content-Type": "application/json", "Retry-After": "0" });
        res.end(JSON.stringify({ status }));
        return;
      }

      // Async status monitor for undeclared Restart POST LRO.
      if (pathname.endsWith("/operationStatuses/op-restart-1")) {
        restartPollCounter++;
        const status = restartPollCounter >= 2 ? "Succeeded" : "InProgress";
        res.writeHead(200, { "Content-Type": "application/json", "Retry-After": "0" });
        res.end(JSON.stringify({ status }));
        return;
      }

      // Async status monitor for Export POST (delivers result in status monitor instead of Location -> LRO-FINAL-STATE-DRIFT).
      if (pathname.endsWith("/operationStatuses/op-export-1")) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            status: "Succeeded",
            properties: {
              downloadUrl:
                "https://contoso.blob.core.windows.net/export/data.json?sig=SuperSecretSasSignature123",
            },
          }),
        );
        return;
      }

      // Widget PUT & GET (intentionally drops `properties.droppedField` to trigger ROUNDTRIP-MUTABILITY-DRIFT, and returns malformed 404 on missing widget).
      if (
        pathname.endsWith("/providers/Microsoft.MockWidget/widgets/missing-widget") &&
        method === "GET"
      ) {
        // Malformed error envelope missing { error: { code, message } }!
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ message: "Not found without OData error wrapper" }));
        return;
      }

      if (pathname.endsWith("/providers/Microsoft.MockWidget/widgets/bbx-w1")) {
        if (method === "PUT") {
          res.writeHead(201, {
            "Content-Type": "application/json",
            "Azure-AsyncOperation": `${baseUrl}/subscriptions/${REAL_SUB_ID}/providers/Microsoft.MockWidget/locations/eastus/operationStatuses/op-put-1?api-version=2025-01-01`,
            "Retry-After": "0",
          });
          res.end(
            JSON.stringify({
              id: pathname,
              name: "bbx-w1",
              type: "Microsoft.MockWidget/widgets",
              location: "eastus",
              properties: {
                skuTier: "Standard",
                provisioningState: "Creating",
              },
            }),
          );
          return;
        }
        if (method === "GET") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              id: pathname,
              name: "bbx-w1",
              type: "Microsoft.MockWidget/widgets",
              location: "eastus",
              properties: {
                skuTier: "Standard",
                provisioningState: "Succeeded",
              },
            }),
          );
          return;
        }
      }

      // Widgets List with nextLink pagination.
      if (pathname.endsWith("/providers/Microsoft.MockWidget/widgets") && method === "GET") {
        const page = reqUrl.searchParams.get("page");
        if (page === "2") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ value: [] }));
        } else {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              value: [
                {
                  id: `${pathname}/bbx-w1`,
                  name: "bbx-w1",
                  type: "Microsoft.MockWidget/widgets",
                  location: "eastus",
                  properties: { skuTier: "Standard", provisioningState: "Succeeded" },
                },
              ],
              nextLink: `${baseUrl}${pathname}?api-version=2025-01-01&page=2`,
            }),
          );
        }
        return;
      }

      // Restart POST: spec says sync 200, service actually returns 202 + Azure-AsyncOperation!
      if (pathname.endsWith("/widgets/bbx-w1/restart") && method === "POST") {
        res.writeHead(202, {
          "Content-Type": "application/json",
          "Azure-AsyncOperation": `${baseUrl}/subscriptions/${REAL_SUB_ID}/providers/Microsoft.MockWidget/locations/eastus/operationStatuses/op-restart-1?api-version=2025-01-01`,
          "Retry-After": "0",
        });
        res.end();
        return;
      }

      // Export POST: spec says final-state-via=location, service uses Azure-AsyncOperation only!
      if (pathname.endsWith("/widgets/bbx-w1/export") && method === "POST") {
        res.writeHead(202, {
          "Content-Type": "application/json",
          "Azure-AsyncOperation": `${baseUrl}/subscriptions/${REAL_SUB_ID}/providers/Microsoft.MockWidget/locations/eastus/operationStatuses/op-export-1?api-version=2025-01-01`,
          "Retry-After": "0",
        });
        res.end();
        return;
      }

      // ListKeys POST: returns sensitive keys + connectionString to verify sanitization!
      if (pathname.endsWith("/widgets/bbx-w1/listKeys") && method === "POST") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            primaryKey: "LIVE_SUPER_SECRET_KEY_ABC999",
            connectionString:
              "Endpoint=https://bbx-w1.mock.io;Id=abcd;Secret=LIVE_CONNECTION_SECRET_XYZ",
          }),
        );
        return;
      }

      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { code: "NotFound", message: "Unknown route" } }));
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });
    server.keepAliveTimeout = 60_000;
    servers.push(server);
    const addr = server.address() as { port: number };
    baseUrl = `http://127.0.0.1:${addr.port}`;

    // 1. Discover TypeSpec inventory in-memory.
    await discoverSpecInventory({
      specPath: tspProjectDir,
      apiVersion: "2025-01-01",
      workDir,
      armBaseUrl: baseUrl,
      subscriptionId: REAL_SUB_ID,
      location: "eastus",
    });

    // 2. Create disposable test RG.
    const { rgName } = await createDisposableResourceGroup({
      workDir,
      bearerToken: MOCK_TOKEN,
    });
    expect(rgName.startsWith("rg-arm-blackbox-")).toBe(true);

    const rgPrefix = `/subscriptions/${REAL_SUB_ID}/resourceGroups/${rgName}/providers/Microsoft.MockWidget`;

    // 3a. Negative 404 precheck catches malformed non-OData error envelope.
    const negRes = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Widgets_Get",
        scenario: "not-found",
        expectError: true,
        pathOrUrl: `${rgPrefix}/widgets/missing-widget`,
      },
    });
    expect(
      negRes.trace.discrepancies.some((d) => d.ruleId === DISCREPANCY_RULES.ERROR_ENVELOPE_DRIFT),
    ).toBe(true);

    // 3b. Widget PUT LRO polls to completion and detects ROUNDTRIP-MUTABILITY-DRIFT on droppedField.
    const putBody = {
      location: "eastus",
      properties: {
        skuTier: "Standard",
        droppedField: "should-have-round-tripped",
      },
    };
    const putRes = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Widgets_CreateOrUpdate",
        pathOrUrl: `${rgPrefix}/widgets/bbx-w1`,
        body: putBody,
        pollIntervalMs: 10,
      },
    });
    expect(putRes.trace.observedLro.detected).toBe(true);
    expect(putRes.trace.observedLro.pollCount).toBe(2);
    expect(putRes.trace.observedLro.terminalProvisioningState).toBe("Succeeded");
    expect(
      putRes.trace.discrepancies.some(
        (d) => d.ruleId === DISCREPANCY_RULES.ROUNDTRIP_MUTABILITY_DRIFT,
      ),
    ).toBe(true);

    // 3c. Widget GET + List (follows nextLink!).
    await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Widgets_Get",
        pathOrUrl: `${rgPrefix}/widgets/bbx-w1`,
      },
    });
    const listRes = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Widgets_ListByResourceGroup",
        pathOrUrl: `${rgPrefix}/widgets`,
      },
    });
    expect(listRes.trace.exchanges.some((ex) => ex.step === "next-page")).toBe(true);

    // 3d. Restart POST catches LRO-UNDECLARED + STATUS-CODE-DRIFT!
    const restartRes = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Widgets_Restart",
        pathOrUrl: `${rgPrefix}/widgets/bbx-w1/restart`,
        pollIntervalMs: 10,
      },
    });
    expect(restartRes.trace.observedLro.detected).toBe(true);
    expect(restartRes.trace.observedLro.pollCount).toBe(2);
    expect(
      restartRes.trace.discrepancies.some((d) => d.ruleId === DISCREPANCY_RULES.LRO_UNDECLARED),
    ).toBe(true);
    expect(
      restartRes.trace.discrepancies.some((d) => d.ruleId === DISCREPANCY_RULES.STATUS_CODE_DRIFT),
    ).toBe(true);

    // 3e. Export POST catches LRO-FINAL-STATE-DRIFT!
    const exportRes = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Widgets_Export",
        pathOrUrl: `${rgPrefix}/widgets/bbx-w1/export`,
        pollIntervalMs: 10,
      },
    });
    expect(
      exportRes.trace.discrepancies.some(
        (d) => d.ruleId === DISCREPANCY_RULES.LRO_FINAL_STATE_DRIFT,
      ),
    ).toBe(true);

    // 3f. ListKeys POST succeeds and captures secret response for sanitization check.
    await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Widgets_ListKeys",
        pathOrUrl: `${rgPrefix}/widgets/bbx-w1/listKeys`,
      },
    });

    // 4. Generate sanitized real-life examples and validate directly against TypeSpec!
    const examples = await generateLiveExamples({
      workDir,
      writeToSpec: false,
      validateWithTypeSpec: true,
    });
    expect(examples.length).toBe(6);

    const putExampleArtifact = examples.find((e) => e.operationId === "Widgets_CreateOrUpdate")!;
    expect(putExampleArtifact.schemaValid).toBe(true);
    const putExampleJson = fs.readFileSync(putExampleArtifact.scratchPath, "utf8");
    const putExampleParsed = JSON.parse(putExampleJson) as {
      responses: Record<string, unknown>;
    };
    // Dual LRO responses (201 initial + 200 terminal) populated!
    expect(putExampleParsed.responses["201"]).toBeDefined();
    expect(putExampleParsed.responses["200"]).toBeDefined();
    // Real subscription ID and disposable RG name sanitized!
    expect(putExampleJson).not.toContain(REAL_SUB_ID);
    expect(putExampleJson).not.toContain(rgName);
    expect(putExampleJson).toContain("00000000-0000-0000-0000-000000000000");
    expect(putExampleJson).toContain("contosoResourceGroup");

    // Verify secrets in ListKeys example are scrubbed and TypeSpec-valid!
    const keysExampleArtifact = examples.find((e) => e.operationId === "Widgets_ListKeys")!;
    expect(keysExampleArtifact.schemaValid).toBe(true);
    const keysExampleJson = fs.readFileSync(keysExampleArtifact.scratchPath, "utf8");
    expect(keysExampleJson).not.toContain("LIVE_SUPER_SECRET_KEY_ABC999");
    expect(keysExampleJson).not.toContain("LIVE_CONNECTION_SECRET_XYZ");
    expect(keysExampleJson).toContain("<redacted>");

    // Verify systemData email PII and ARM signed query params are scrubbed!
    const scrubbedSystemData = sanitizePayload(
      {
        systemData: {
          createdBy: "developer@realdomain.com",
          lastModifiedBy: "developer@realdomain.com",
        },
        asyncUrl:
          "https://management.azure.com/subscriptions/11111111-2222-3333-4444-555555555555/operationsStatus/op1?api-version=2025-01-01&c=MIIBIjANBg&s=RawSig&h=RawHash",
      },
      { subscriptionId: "11111111-2222-3333-4444-555555555555" },
    ) as { systemData: { createdBy: string; lastModifiedBy: string }; asyncUrl: string };
    expect(scrubbedSystemData.systemData.createdBy).toBe("user@contoso.com");
    expect(scrubbedSystemData.systemData.lastModifiedBy).toBe("user@contoso.com");
    expect(scrubbedSystemData.asyncUrl).not.toContain("MIIBIjANBg");
    expect(scrubbedSystemData.asyncUrl).toContain("c=<redacted>");

    // Restart example came from an undeclared 202 response so TypeSpec validator flags the undocumented 202!
    const restartExampleArtifact = examples.find((e) => e.operationId === "Widgets_Restart")!;
    expect(restartExampleArtifact.schemaValid).toBe(false);

    // 5. Delete disposable RG and render report (100% operation coverage!).
    const delRg = await deleteDisposableResourceGroup({
      workDir,
      bearerToken: MOCK_TOKEN,
    });
    expect(delRg.cleanupStatus).toBe("deleted");

    const { report, markdownPath } = await buildSummaryReport(workDir);
    expect(report.coverageSummary.totalOperations).toBe(6);
    expect(report.coverageSummary.testedOperations).toBe(6);
    expect(report.coverageSummary.coveragePercent).toBe(100);
    expect(report.discrepancySummary.blocking).toBeGreaterThanOrEqual(3);
    expect(report.discrepancies.some((d) => d.sourceLocation?.file.endsWith("main.tsp"))).toBe(
      true,
    );
    expect(fs.existsSync(markdownPath)).toBe(true);
  });

  it("auto-interpolates URL slots + priorPutBody and enforces all V2 security, LRO, multi-page, secret, and AST constraint rules", async () => {
    const tempRoot = makeTempDir();
    const projectDir = path.join(tempRoot, "V2Vault.Management");
    fs.mkdirSync(projectDir, { recursive: true });
    fs.writeFileSync(path.join(projectDir, "tspconfig.yaml"), "{}\n", "utf8");

    const v2Tsp = `
import "@typespec/http";
import "@typespec/rest";
import "@typespec/versioning";
import "@typespec/openapi";
import "@azure-tools/typespec-azure-core";
import "@azure-tools/typespec-azure-resource-manager";

using TypeSpec.Http;
using TypeSpec.Rest;
using TypeSpec.Versioning;
using TypeSpec.OpenAPI;
using Azure.Core;
using Azure.ResourceManager;

@armProviderNamespace
@service(#{ title: "V2VaultClient" })
@versioned(Versions)
@armCommonTypesVersion(Azure.ResourceManager.CommonTypes.Versions.v5)
namespace Microsoft.V2Vault;

enum Versions {
  v2025_03_01: "2025-03-01",
}

model CredentialItem {
  @secret
  opaqueMaterial: string;
}

model VaultProperties {
  @minValue(3600)
  @maxValue(86400)
  retentionSeconds?: int32;
  persistedFlag?: string;
  primaryCred?: CredentialItem;
  secondaryCred?: CredentialItem;
  credList?: CredentialItem[];
  @visibility(Lifecycle.Read)
  provisioningState?: ResourceProvisioningState;
}

model Vault is TrackedResource<VaultProperties> {
  ...ResourceNameParameter<Vault>;
}

model ConnectionProperties {
  status?: string;
  @visibility(Lifecycle.Read)
  provisioningState?: ResourceProvisioningState;
}

@parentResource(Vault)
model PrivateConn is ProxyResource<ConnectionProperties> {
  ...ResourceNameParameter<PrivateConn>;
}

model BackupOutput {
  archiveUri: string;
}

@armResourceOperations
interface Vaults {
  @operationId("Vaults_Get")
  get is ArmResourceRead<Vault>;

  @operationId("Vaults_CreateOrUpdate")
  createOrUpdate is ArmResourceCreateOrReplaceAsync<Vault>;

  @operationId("Vaults_ListByResourceGroup")
  listByResourceGroup is ArmResourceListByParent<Vault>;

  @operationId("Vaults_Delete")
  delete is ArmResourceDeleteWithoutOkAsync<Vault>;

  @operationId("Vaults_Backup")
  backup is ArmResourceActionAsync<
    Vault,
    {
      @header("x-custom-credential") @secret customCredential: string;
    },
    BackupOutput
  >;
}

@armResourceOperations
interface PrivateConns {
  @operationId("PrivateConns_ListByVault")
  listByVault is ArmResourceListByParent<PrivateConn>;

  @operationId("PrivateConns_Get")
  get is ArmResourceRead<PrivateConn>;
}
`;
    fs.writeFileSync(path.join(projectDir, "main.tsp"), `${v2Tsp.trim()}\n`, "utf8");

    const workDir = path.join(tempRoot, "work-v2");
    let baseUrl = "";
    let createdVaultName = "";
    let emptyGetMode = false;
    const failDeleteLro = true;
    let slowFixtureMode = true;
    const v2RgStore = new Map<string, Record<string, unknown>>();

    const server = http.createServer((req, res) => {
      const reqUrl = new URL(req.url ?? "/", baseUrl);
      const pathname = reqUrl.pathname;
      const method = req.method?.toUpperCase() ?? "GET";

      // Disposable RG lifecycle with per-run ownership tags (#7890)
      if (
        /^\/subscriptions\/[^/]+\/resourcegroups\/rg-arm-blackbox-/i.test(pathname) &&
        !pathname.includes("/providers/")
      ) {
        const key = pathname.toLowerCase();
        if (method === "GET") {
          const existing = v2RgStore.get(key);
          if (!existing) {
            res.writeHead(404, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({ error: { code: "ResourceGroupNotFound", message: "Not found" } }),
            );
          } else {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(JSON.stringify(existing));
          }
          return;
        }
        if (method === "PUT") {
          const chunks: Buffer[] = [];
          req.on("data", (c: Buffer) => chunks.push(c));
          req.on("end", () => {
            const parsed = JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}") as Record<
              string,
              unknown
            >;
            const record = { id: pathname, location: "eastus", ...parsed };
            v2RgStore.set(key, record);
            res.writeHead(201, { "Content-Type": "application/json" });
            res.end(JSON.stringify(record));
          });
          return;
        }
        if (method === "DELETE") {
          v2RgStore.delete(key);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ id: pathname }));
          return;
        }
      }

      // External UAMI fixture to test LRO timeout detection (#23/#24)
      if (pathname.includes("/providers/Microsoft.ManagedIdentity/userAssignedIdentities/")) {
        if (method === "PUT") {
          res.writeHead(201, {
            "Content-Type": "application/json",
            "Azure-AsyncOperation": `${baseUrl}/uami-op`,
          });
          res.end(JSON.stringify({ id: pathname, properties: { provisioningState: "Creating" } }));
          return;
        }
      }
      if (pathname === "/uami-op") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: slowFixtureMode ? "Creating" : "Succeeded" }));
        return;
      }

      // Backup POST with BOTH Azure-AsyncOperation (containing monitor properties) AND Location (#14)
      if (pathname.endsWith("/backup") && method === "POST") {
        res.writeHead(202, {
          "Content-Type": "application/json",
          "Azure-AsyncOperation": `${baseUrl}/backup-monitor`,
          Location: `${baseUrl}/backup-result`,
          "Retry-After": "0",
        });
        res.end();
        return;
      }
      if (pathname === "/backup-monitor") {
        res.writeHead(200, { "Content-Type": "application/json" });
        // Monitor includes non-result `properties` metadata; harness must still fetch Location (#14)!
        res.end(JSON.stringify({ status: "Succeeded", properties: { stage: "completed" } }));
        return;
      }
      if (pathname === "/backup-result") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ archiveUri: "https://contoso.blob.core.windows.net/bk.zip" }));
        return;
      }

      // Delete LRO that fails asynchronously (#19/#20)
      if (pathname.includes("/providers/Microsoft.V2Vault/vaults/") && method === "DELETE") {
        res.writeHead(202, {
          "Content-Type": "application/json",
          "Azure-AsyncOperation": `${baseUrl}/delete-monitor`,
          "Retry-After": "0",
        });
        res.end();
        return;
      }
      if (pathname === "/delete-monitor") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: failDeleteLro ? "Failed" : "Succeeded" }));
        return;
      }

      // Child PrivateConns list & get (tests List-discovered child name auto-binding!)
      if (pathname.endsWith("/privateConns") && method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            value: [
              {
                id: `${pathname}/server-conn-42`,
                name: "server-conn-42",
                type: "Microsoft.V2Vault/vaults/privateConns",
                properties: { status: "Approved", provisioningState: "Succeeded" },
              },
            ],
          }),
        );
        return;
      }
      if (pathname.endsWith("/privateConns/server-conn-42") && method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            id: pathname,
            name: "server-conn-42",
            type: "Microsoft.V2Vault/vaults/privateConns",
            properties: { status: "Approved", provisioningState: "Succeeded" },
          }),
        );
        return;
      }

      // 3-page Vaults List (#15/#16/#17)
      if (pathname.endsWith("/providers/Microsoft.V2Vault/vaults") && method === "GET") {
        const page = reqUrl.searchParams.get("page") ?? "1";
        if (page === "1") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              value: [
                {
                  id: `${pathname}/${createdVaultName}`,
                  name: createdVaultName,
                  type: "Microsoft.V2Vault/vaults",
                  location: "eastus",
                },
              ],
              nextLink: `${baseUrl}${pathname}?api-version=2025-03-01&page=2`,
            }),
          );
          return;
        }
        if (page === "2") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              value: [],
              nextLink: `${baseUrl}${pathname}?api-version=2025-03-01&page=3`,
            }),
          );
          return;
        }
        // Page 3 has an invalid retentionSeconds = 5 (< @minValue(3600)) to prove page-3 schema validation runs (#15–#18, #28)!
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            value: [
              {
                id: `${pathname}/bad-page3`,
                name: "bad-page3",
                type: "Microsoft.V2Vault/vaults",
                location: "eastus",
                properties: { retentionSeconds: 5 },
              },
            ],
          }),
        );
        return;
      }

      // Vaults PUT & GET
      const vaultMatch = /\/providers\/Microsoft\.V2Vault\/vaults\/([^/]+)$/.exec(pathname);
      if (vaultMatch) {
        const vName = vaultMatch[1];
        if (vName.startsWith("missing-") && method === "GET") {
          res.writeHead(404, { "Content-Type": "application/json" });
          // Malformed error envelope to test #21/#22 (status stays pending!)
          res.end(JSON.stringify({ badError: "missing OData error wrapper" }));
          return;
        }
        if (method === "PUT") {
          createdVaultName = vName;
          res.writeHead(200, { "Content-Type": "application/json" });
          // PUT echoes persistedFlag, whereas subsequent GET drops it (#26/#27)!
          res.end(
            JSON.stringify({
              id: pathname,
              name: vName,
              type: "Microsoft.V2Vault/vaults",
              location: "eastus",
              properties: {
                retentionSeconds: 3600,
                persistedFlag: "present-on-put",
                primaryCred: { opaqueMaterial: "RAW_PRIMARY_SECRET" },
                secondaryCred: { opaqueMaterial: "RAW_SECONDARY_SECRET" },
                credList: [{ opaqueMaterial: "RAW_ARRAY_SECRET" }],
                provisioningState: "Succeeded",
              },
            }),
          );
          return;
        }
        if (method === "GET") {
          if (emptyGetMode) {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end("");
            return;
          }
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              id: pathname,
              name: vName,
              type: "Microsoft.V2Vault/vaults",
              location: "eastus",
              properties: {
                retentionSeconds: 3600,
                // persistedFlag intentionally omitted on GET!
                primaryCred: { opaqueMaterial: "RAW_PRIMARY_SECRET" },
                secondaryCred: { opaqueMaterial: "RAW_SECONDARY_SECRET" },
                credList: [{ opaqueMaterial: "RAW_ARRAY_SECRET" }],
                provisioningState: "Succeeded",
              },
            }),
          );
          return;
        }
      }

      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { code: "NotFound", message: "Not found" } }));
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });
    server.keepAliveTimeout = 60_000;
    servers.push(server);
    baseUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

    await discoverSpecInventory({
      specPath: projectDir,
      apiVersion: "2025-03-01",
      workDir,
      armBaseUrl: baseUrl,
      subscriptionId: REAL_SUB_ID,
      location: "eastus",
    });

    await createDisposableResourceGroup({ workDir, bearerToken: MOCK_TOKEN });

    // Fixture LRO timeout throws instead of returning an unready Creating fixture (#23/#24).
    await expect(
      provisionExternalFixture({
        workDir,
        kind: "managed-identity",
        pollIntervalMs: 5,
        maxPollAttempts: 3,
        bearerToken: MOCK_TOKEN,
      }),
    ).rejects.toThrow(/timed out|non-ready/);
    slowFixtureMode = false;

    // Conflicting api-version in query or URL is rejected (#12/#13).
    await expect(
      executeOperationProbe({
        workDir,
        bearerToken: MOCK_TOKEN,
        input: {
          operationId: "Vaults_ListByResourceGroup",
          query: { "api-version": "1999-01-01" },
        },
      }),
    ).rejects.toThrow(/Conflicting api-version/);

    // Negative 404 with malformed error envelope records discrepancy while keeping coverage "pending" (#21/#22).
    const negGet = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Vaults_Get",
        expectError: true,
      },
    });
    expect(
      negGet.trace.discrepancies.some((d) => d.ruleId === DISCREPANCY_RULES.ERROR_ENVELOPE_DRIFT),
    ).toBe(true);
    const reportAfterNeg = await buildSummaryReport(workDir);
    expect(reportAfterNeg.report.coverageSummary.testedOperations).toBe(0);

    // PUT without pathOrUrl auto-interpolates pathTemplate; out-of-range @minValue(3600) on property is caught (#28/#29)!
    const putProbe = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Vaults_CreateOrUpdate",
        body: {
          location: "eastus",
          properties: {
            retentionSeconds: 10, // < @minValue(3600) on ModelProperty!
            persistedFlag: "present-on-put",
            primaryCred: { opaqueMaterial: "REQ_PRIMARY_SECRET" },
            secondaryCred: { opaqueMaterial: "REQ_SECONDARY_SECRET" },
            credList: [{ opaqueMaterial: "REQ_ARRAY_SECRET" }],
          },
        },
      },
    });
    expect(createdVaultName).toMatch(/^bbx-/);
    expect(putProbe.trace.requestSchemaErrors.some((e) => e.code === "MIN_VALUE_VIOLATION")).toBe(
      true,
    );

    // Empty body on GET when TypeSpec requires Vault model triggers MISSING_REQUIRED_RESPONSE_BODY (#30/#31).
    emptyGetMode = true;
    const emptyGet = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: { operationId: "Vaults_Get", scenario: "empty-body" },
    });
    expect(
      emptyGet.trace.responseSchemaErrors.some((e) => e.code === "MISSING_REQUIRED_RESPONSE_BODY"),
    ).toBe(true);
    emptyGetMode = false;

    // Subsequent GET without pathOrUrl OR manual priorPutBody auto-reuses createdVaultName AND auto-attaches priorPutBody,
    // catching persistedFlag dropped on GET (#26/#27)!
    const okGet = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: { operationId: "Vaults_Get" },
    });
    expect(
      okGet.trace.discrepancies.some(
        (d) => d.ruleId === DISCREPANCY_RULES.ROUNDTRIP_MUTABILITY_DRIFT,
      ),
    ).toBe(true);

    // 3-page List traverses all 3 pages AND validates page 3's @minValue violation (#15–#18, #28).
    const listProbe = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: { operationId: "Vaults_ListByResourceGroup" },
    });
    expect(listProbe.trace.exchanges.filter((e) => e.step === "next-page").length).toBe(2);
    expect(listProbe.trace.responseSchemaErrors.some((e) => e.code === "MIN_VALUE_VIOLATION")).toBe(
      true,
    );

    // Child List harvests "server-conn-42", and child GET without pathOrUrl auto-binds {privateConnName} = "server-conn-42"!
    await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: { operationId: "PrivateConns_ListByVault" },
    });
    const childGet = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: { operationId: "PrivateConns_Get" },
    });
    expect(childGet.trace.probeSucceeded).toBe(true);
    expect(childGet.trace.exchanges[0].request.url).toContain("/privateConns/server-conn-42");

    // POST Backup with final-state-via="location" fetches Location GET despite monitor properties, and redacts @secret header (#10/#11, #14).
    const backupProbe = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Vaults_Backup",
        headers: { "x-custom-credential": "TOP_SECRET_HEADER_MATERIAL" },
        pollIntervalMs: 5,
      },
    });
    expect(backupProbe.trace.observedLro.finalResultSource).toBe("location-body");
    expect(backupProbe.trace.exchanges.some((e) => e.step === "final-get")).toBe(true);

    // Failed LRO on DELETE marks probe failed_service_error and is excluded from examples & positive coverage (#19/#20).
    const failedDel = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Vaults_Delete",
        body: undefined,
        pollIntervalMs: 5,
      },
    });
    expect(failedDel.trace.probeSucceeded).toBe(false);
    expect(failedDel.trace.observedLro.completionStatus).toBe("failed");

    const generated = await generateLiveExamples({ workDir, validateWithTypeSpec: true });
    // Failed DELETE must NOT produce a fabricated example (#19/#20)!
    expect(generated.some((g) => g.operationId === "Vaults_Delete")).toBe(false);

    // Verify reused @secret models (primaryCred + secondaryCred), array secrets (credList[]), and standalone @secret header are ALL redacted (#5–#11)!
    const putExText = fs.readFileSync(
      generated.find((g) => g.operationId === "Vaults_CreateOrUpdate")!.scratchPath,
      "utf8",
    );
    expect(putExText).not.toContain("REQ_PRIMARY_SECRET");
    expect(putExText).not.toContain("REQ_SECONDARY_SECRET");
    expect(putExText).not.toContain("REQ_ARRAY_SECRET");
    expect(putExText).not.toContain("RAW_PRIMARY_SECRET");
    expect(putExText).not.toContain("RAW_SECONDARY_SECRET");
    expect(putExText).not.toContain("RAW_ARRAY_SECRET");

    const backupExArtifact = generated.find((g) => g.operationId === "Vaults_Backup")!;
    expect(backupExArtifact.schemaValid).toBe(true);
    const backupExText = fs.readFileSync(backupExArtifact.scratchPath, "utf8");
    expect(backupExText).not.toContain("TOP_SECRET_HEADER_MATERIAL");
    expect(backupExText).toContain("https://contoso.blob.core.windows.net/bk.zip");

    // Verify nested 2D array secret paths, dotted/empty dictionary keys, @secret container descendants,
    // recursive cycle folding, and @pattern-safe secret placeholders (#4080, #7732, #7801, #7984, #8063)!
    const dictSanitized = sanitizePayload(
      {
        credentials: {
          "dotted.key.name": { value: "DOTTED_KEY_SECRET_123" },
          "": { value: "EMPTY_KEY_SECRET_456" },
        },
        matrix: [[{ secretTokenVal: "MATRIX_2D_SECRET_789" }]],
        properties: {
          configurationProtectedSettings: {
            opaqueMaterial: "CONTAINER_CHILD_SECRET",
            nested: { deepValue: "CONTAINER_DEEP_SECRET" },
          },
          alnumPassword: "SuperSecretAlnumPassword99",
        },
        tree: {
          opaqueNodeSecret: "ROOT_NODE_SECRET",
          children: [
            {
              opaqueNodeSecret: "CHILD_DEPTH1_SECRET",
              children: [{ opaqueNodeSecret: "CHILD_DEPTH2_SECRET" }],
            },
          ],
        },
      },
      {
        extraSecretPropertyPaths: [
          "credentials.*.value",
          "matrix[][].secretTokenVal",
          "properties.configurationProtectedSettings",
          "properties.alnumPassword",
          "tree.opaqueNodeSecret",
        ],
        secretCycleRules: [{ basePath: "tree", repeatPath: "children[]" }],
        secretConstraints: {
          "properties.alnumpassword": {
            minLength: 8,
            maxLength: 80,
            pattern: "^[a-zA-Z0-9]{0,80}$",
          },
        },
      },
    ) as {
      credentials: Record<string, { value: string }>;
      matrix: Array<Array<{ secretTokenVal: string }>>;
      properties: {
        configurationProtectedSettings: { opaqueMaterial: string; nested: { deepValue: string } };
        alnumPassword: string;
      };
      tree: {
        opaqueNodeSecret: string;
        children: Array<{
          opaqueNodeSecret: string;
          children?: Array<{ opaqueNodeSecret: string }>;
        }>;
      };
    };
    expect(dictSanitized.credentials["dotted.key.name"].value).toBe("<redacted>");
    expect(dictSanitized.credentials[""].value).toBe("<redacted>");
    expect(dictSanitized.matrix[0][0].secretTokenVal).toBe("<redacted>");
    expect(dictSanitized.properties.configurationProtectedSettings.opaqueMaterial).toBe(
      "<redacted>",
    );
    expect(dictSanitized.properties.configurationProtectedSettings.nested.deepValue).toBe(
      "<redacted>",
    );
    expect(dictSanitized.properties.alnumPassword).toMatch(/^[a-zA-Z0-9]{8,80}$/);
    expect(dictSanitized.properties.alnumPassword).not.toContain("SuperSecret");
    expect(dictSanitized.tree.opaqueNodeSecret).toBe("<redacted>");
    expect(dictSanitized.tree.children[0].opaqueNodeSecret).toBe("<redacted>");
    expect(dictSanitized.tree.children[0].children![0].opaqueNodeSecret).toBe("<redacted>");

    // Deep >32-level recursive secret model completes cycle reduction, and budget exhaustion fails closed!
    let deepNode: Record<string, unknown> = { opaqueNodeSecret: "DEEP_LEVEL_40_SECRET" };
    for (let d = 0; d < 40; d++) {
      deepNode = { children: [deepNode] };
    }
    const deepSanitized = sanitizePayload(
      { tree: deepNode },
      {
        extraSecretPropertyPaths: ["tree.opaqueNodeSecret"],
        secretCycleRules: [{ basePath: "tree", repeatPath: "children[]" }],
      },
    );
    expect(JSON.stringify(deepSanitized)).not.toContain("DEEP_LEVEL_40_SECRET");
    expect(JSON.stringify(deepSanitized)).toContain("<redacted>");

    expect(() =>
      sanitizePayload(
        { tree: deepNode },
        {
          extraSecretPropertyPaths: ["tree.opaqueNodeSecret"],
          secretCycleRules: [{ basePath: "tree", repeatPath: "children[]" }],
          maxSecretCycleVariants: 8,
        },
      ),
    ).toThrow(/exceeded expansion budget/);

    // Failed or timed-out PUT LRO must NOT emit false ROUNDTRIP-MUTABILITY-DRIFT!
    const vaultPutContract = ledgerRawSnapshotForContract(workDir, "Vaults_CreateOrUpdate");
    const timedOutPutDiscrepancies = analyzeBehavioralDiscrepancies({
      contract: vaultPutContract,
      expectError: false,
      exchanges: [
        {
          step: "initial",
          timestamp: new Date().toISOString(),
          durationMs: 10,
          request: {
            method: "PUT",
            url: `${baseUrl}/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-arm-blackbox-test/providers/Microsoft.V2Vault/vaults/v-fail?api-version=2025-03-01`,
            headers: {},
            body: { location: "eastus", properties: { persistedFlag: "submitted-val" } },
          },
          response: {
            status: 201,
            headers: { "azure-asyncoperation": `${baseUrl}/monitors/put-1` },
            body: { properties: { provisioningState: "Creating" } },
          },
        },
        {
          step: "poll",
          timestamp: new Date().toISOString(),
          durationMs: 10,
          request: { method: "GET", url: `${baseUrl}/monitors/put-1`, headers: {} },
          response: {
            status: 200,
            headers: {},
            body: { status: "Failed", error: { code: "InternalError", message: "boom" } },
          },
        },
      ],
      observedLro: {
        detected: true,
        detectionSignals: ["azure-asyncoperation"],
        pollingHeaderUsed: "azure-asyncoperation",
        pollCount: 1,
        completionStatus: "failed",
        terminalProvisioningState: "Failed",
      },
      requestSchemaErrors: [],
      responseSchemaErrors: [],
    });
    expect(
      timedOutPutDiscrepancies.some(
        (d) => d.ruleId === DISCREPANCY_RULES.ROUNDTRIP_MUTABILITY_DRIFT,
      ),
    ).toBe(false);

    // Ambiguous multi-project root directory is rejected (#8112)!
    const multiRoot = path.join(tempRoot, "multi-spec-root", "resource-manager");
    fs.mkdirSync(path.join(multiRoot, "SubA"), { recursive: true });
    fs.mkdirSync(path.join(multiRoot, "SubB"), { recursive: true });
    fs.writeFileSync(path.join(multiRoot, "SubA", "tspconfig.yaml"), "{}\n", "utf8");
    fs.writeFileSync(path.join(multiRoot, "SubA", "main.tsp"), "\n", "utf8");
    fs.writeFileSync(path.join(multiRoot, "SubB", "tspconfig.yaml"), "{}\n", "utf8");
    fs.writeFileSync(path.join(multiRoot, "SubB", "main.tsp"), "\n", "utf8");
    await expect(
      discoverSpecInventory({
        specPath: multiRoot,
        workDir: path.join(tempRoot, "work-ambig"),
      }),
    ).rejects.toThrow(/Ambiguous TypeSpec root/);

    // Re-running discover or switching RG while active disposable RG exists is blocked (#4360, #4409)!
    await expect(
      discoverSpecInventory({
        specPath: projectDir,
        apiVersion: "2025-03-01",
        workDir,
      }),
    ).rejects.toThrow(/Refusing to overwrite/);
    await expect(
      createDisposableResourceGroup({
        workDir,
        rgName: "rg-arm-blackbox-other-999999",
        bearerToken: MOCK_TOKEN,
      }),
    ).rejects.toThrow(/Cannot switch disposable Resource Group/);

    // Positive probe with mismatched HTTP method or off-contract route is rejected (#7862)!
    await expect(
      executeOperationProbe({
        workDir,
        bearerToken: MOCK_TOKEN,
        input: {
          operationId: "Vaults_Delete",
          method: "GET",
        },
      }),
    ).rejects.toThrow(/must use declared HTTP method/);

    // Private-endpoint fixture rejects unrecorded / external target-resource-id (#7920)!
    await expect(
      provisionExternalFixture({
        workDir,
        kind: "private-endpoint",
        targetPrivateLinkResourceId: `/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-production/providers/Microsoft.V2Vault/vaults/prod-vault`,
        groupIds: ["vaults"],
        bearerToken: MOCK_TOKEN,
      }),
    ).rejects.toThrow(/Blocked private-endpoint fixture/);

    // Verify Markdown backslash + pipe escaping in report (CodeQL #1).
    const ledgerRaw = JSON.parse(
      fs.readFileSync(path.join(workDir, "coverage-ledger.json"), "utf8"),
    ) as CoverageLedger;
    ledgerRaw.coverage.Vaults_Delete.blockerReason = "Path C:\\foo\\bar|injected";
    fs.writeFileSync(
      path.join(workDir, "coverage-ledger.json"),
      JSON.stringify(ledgerRaw, null, 2),
      "utf8",
    );
    const finalReport = await buildSummaryReport(workDir);
    const mdText = fs.readFileSync(finalReport.markdownPath, "utf8");
    expect(mdText).toContain("Path C:\\\\foo\\\\bar\\|injected");
    // Vaults_Delete failed LRO -> only 6 of 7 operations positively covered!
    expect(finalReport.report.coverageSummary.testedOperations).toBe(6);

    // Local interactive HTML report bundle is generated with zero leaked secrets and XSS-safe portal-data.js!
    expect(finalReport.htmlIndexPath).toBeTruthy();
    expect(fs.existsSync(finalReport.htmlIndexPath!)).toBe(true);
    expect(fs.existsSync(path.join(finalReport.htmlDir!, "assets", "styles.css"))).toBe(true);
    expect(fs.existsSync(path.join(finalReport.htmlDir!, "assets", "app.js"))).toBe(true);
    const portalDataJs = fs.readFileSync(
      path.join(finalReport.htmlDir!, "assets", "portal-data.js"),
      "utf8",
    );
    expect(portalDataJs).toContain("window.__ARM_BLACKBOX_PORTAL_DATA__ =");
    expect(portalDataJs).not.toContain("REQ_PRIMARY_SECRET");
    expect(portalDataJs).not.toContain("RAW_PRIMARY_SECRET");
    expect(portalDataJs).not.toContain("TOP_SECRET_HEADER_MATERIAL");
    expect(portalDataJs).not.toContain(REAL_SUB_ID);
  });

  it("supports custom Canary/Dogfood ARM base URLs, base-path prefixes, companion polling origins, and XSS-safe local HTML reports", async () => {
    // 1. Validate Canary / Dogfood / Sovereign URL normalization & token audience inference
    expect(validateAndNormalizeArmBaseUrl("https://eastus2euap.management.azure.com/")).toBe(
      "https://eastus2euap.management.azure.com",
    );
    expect(() => validateAndNormalizeArmBaseUrl("http://eastus2euap.management.azure.com")).toThrow(
      /HTTPS is required/,
    );
    expect(inferArmTokenResource("https://eastus2euap.management.azure.com")).toBe(
      "https://management.azure.com",
    );
    expect(inferArmTokenResource("https://api-dogfood.resources.windows-int.net")).toBe(
      "https://management.core.windows.net/",
    );
    expect(inferArmTokenResource("https://management.usgovcloudapi.net")).toBe(
      "https://management.usgovcloudapi.net",
    );
    expect(inferArmTokenResource("https://management.chinacloudapi.cn")).toBe(
      "https://management.chinacloudapi.cn",
    );
    expect(
      inferArmTokenResource(
        "https://canary-arm.contoso.net/arm-canary",
        "api://custom-canary-audience",
      ),
    ).toBe("api://custom-canary-audience");

    // Regional EUAP canary automatically trusts canonical parent https://management.azure.com for LRO polling / nextLink,
    // while blocking untrusted third-party or insecure origins.
    expect(() =>
      assertTrustedArmOrigin(
        "https://management.azure.com/subscriptions/0000/providers/Microsoft.Foo/locations/eastus2euap/asyncOperations/op1?api-version=2025-01-01",
        "https://eastus2euap.management.azure.com",
      ),
    ).not.toThrow();
    expect(() =>
      assertTrustedArmOrigin(
        "https://api-dogfood.resources.windows-int.net/subscriptions/0000/operationresults/op1",
        "https://eastus2euap.api-dogfood.resources.windows-int.net",
      ),
    ).not.toThrow();
    expect(() =>
      assertTrustedArmOrigin(
        "https://evil.example.com/steal-token",
        "https://eastus2euap.management.azure.com",
      ),
    ).toThrow(/untrusted origin/);

    // 2. End-to-end Canary proxy with base-path prefix (/arm-canary) + separate companion LRO polling origin
    const tempRoot = makeTempDir();
    const projectDir = createMinimalArmMockTypeSpecProject(tempRoot);
    const workDir = path.join(tempRoot, "work-canary");

    let pollServerUrl = "";
    let pollHits = 0;
    const pollServer = http.createServer((req, res) => {
      pollHits++;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          status: pollHits >= 1 ? "Succeeded" : "InProgress",
        }),
      );
      req.resume();
    });
    await new Promise<void>((resolve) => {
      pollServer.listen(0, "127.0.0.1", () => resolve());
    });
    pollServer.keepAliveTimeout = 60_000;
    servers.push(pollServer);
    pollServerUrl = `http://127.0.0.1:${(pollServer.address() as { port: number }).port}`;

    let rgState: Record<string, unknown> | undefined;
    let canaryBaseUrl = "";
    const canaryServer = http.createServer((req, res) => {
      void (async () => {
        const chunks: Buffer[] = [];
        for await (const c of req) {
          chunks.push(c as Buffer);
        }
        const rawBody = Buffer.concat(chunks).toString("utf8");
        const reqUrl = new URL(req.url ?? "/", canaryBaseUrl);
        const pathname = decodeURIComponent(reqUrl.pathname);

        // Every request to the canary server MUST arrive under the /arm-canary prefix!
        if (!pathname.startsWith("/arm-canary/")) {
          res.writeHead(400, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ error: { code: "MissingCanaryPrefix", message: pathname } }));
          return;
        }
        const armPath = pathname.slice("/arm-canary".length);

        if (/^\/subscriptions\/[^/]+\/resourcegroups\/[^/]+$/i.test(armPath)) {
          if (req.method === "GET") {
            if (!rgState) {
              res.writeHead(404, { "Content-Type": "application/json" });
              res.end(JSON.stringify({ error: { code: "ResourceGroupNotFound", message: "404" } }));
            } else {
              res.writeHead(200, { "Content-Type": "application/json" });
              res.end(JSON.stringify(rgState));
            }
            return;
          }
          if (req.method === "PUT") {
            const parsed = JSON.parse(rawBody) as Record<string, unknown>;
            rgState = { id: armPath, location: parsed.location, tags: parsed.tags };
            res.writeHead(201, { "Content-Type": "application/json" });
            res.end(JSON.stringify(rgState));
            return;
          }
          if (req.method === "DELETE") {
            rgState = undefined;
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end("");
            return;
          }
        }

        if (/\/providers\/Microsoft\.MockWidget\/widgets\/[^/]+$/i.test(armPath)) {
          if (req.method === "PUT") {
            res.writeHead(201, {
              "Content-Type": "application/json",
              "Azure-AsyncOperation": `${pollServerUrl}/asyncOps/w-canary-1`,
            });
            res.end(
              JSON.stringify({
                id: armPath,
                name: "bbx-canary-w1",
                type: "Microsoft.MockWidget/widgets",
                location: "eastus",
                tags: { xssCheck: "</script><script>alert(1)</script>" },
                properties: { skuTier: "Standard", provisioningState: "Creating" },
              }),
            );
            return;
          }
          if (req.method === "GET") {
            res.writeHead(200, { "Content-Type": "application/json" });
            res.end(
              JSON.stringify({
                id: armPath,
                name: "bbx-canary-w1",
                type: "Microsoft.MockWidget/widgets",
                location: "eastus",
                tags: { xssCheck: "</script><script>alert(1)</script>" },
                properties: { skuTier: "Standard", provisioningState: "Succeeded" },
              }),
            );
            return;
          }
        }

        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { code: "NotFound", message: armPath } }));
      })();
    });
    await new Promise<void>((resolve) => {
      canaryServer.listen(0, "127.0.0.1", () => resolve());
    });
    canaryServer.keepAliveTimeout = 60_000;
    servers.push(canaryServer);
    canaryBaseUrl = `http://127.0.0.1:${(canaryServer.address() as { port: number }).port}/arm-canary`;

    await discoverSpecInventory({
      specPath: projectDir,
      apiVersion: "2025-01-01",
      workDir,
      armBaseUrl: canaryBaseUrl,
      allowedArmOrigins: [pollServerUrl],
      subscriptionId: REAL_SUB_ID,
      location: "eastus",
    });

    await createDisposableResourceGroup({ workDir, bearerToken: MOCK_TOKEN });
    const putTrace = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Widgets_CreateOrUpdate",
        body: {
          location: "eastus",
          tags: { xssCheck: "</script><script>alert(1)</script>" },
          properties: { skuTier: "Standard" },
        },
        pollIntervalMs: 5,
      },
    });
    expect(putTrace.trace.probeSucceeded).toBe(true);
    expect(pollHits).toBeGreaterThanOrEqual(1);

    const exArtifacts = await generateLiveExamples({ workDir, validateWithTypeSpec: true });
    expect(exArtifacts.length).toBe(1);
    const exText = fs.readFileSync(exArtifacts[0].scratchPath, "utf8");
    // Canary base URL and companion polling origin are scrubbed to canonical https://management.azure.com!
    expect(exText).not.toContain(canaryBaseUrl);
    expect(exText).not.toContain(pollServerUrl);
    expect(exText).toContain("https://management.azure.com/asyncOps/w-canary-1");

    await deleteDisposableResourceGroup({ workDir, bearerToken: MOCK_TOKEN });

    // Mutating probe after RG deletion is rejected immediately (#60602)!
    await expect(
      executeOperationProbe({
        workDir,
        bearerToken: MOCK_TOKEN,
        input: {
          operationId: "Widgets_CreateOrUpdate",
          body: { location: "eastus", properties: { skuTier: "Standard" } },
        },
      }),
    ).rejects.toThrow(/cleanupStatus "deleted"/);

    // Delegating Microsoft.Resources/deployments and RG-level tags/default inside RG are blocked (#60636, #51119)!
    expect(() =>
      assertSafeArmTarget(
        "PUT",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-arm-blackbox-appconfig-abc123/providers/Microsoft.Resources/deployments/nested?api-version=2024-03-01`,
        {
          trustedArmBaseUrl: "https://management.azure.com",
          subscriptionId: REAL_SUB_ID,
          disposableRgName: "rg-arm-blackbox-appconfig-abc123",
          disposableRgCleanupStatus: "active",
          expectedRunId: "run1",
          verifiedRgRunIdTag: "run1",
        },
      ),
    ).toThrow(/Blocked Microsoft\.Resources RG-level mutation/);

    expect(() =>
      assertSafeArmTarget(
        "DELETE",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-arm-blackbox-appconfig-abc123/providers/Microsoft.Resources/tags/default?api-version=2024-03-01`,
        {
          trustedArmBaseUrl: "https://management.azure.com",
          subscriptionId: REAL_SUB_ID,
          disposableRgName: "rg-arm-blackbox-appconfig-abc123",
          disposableRgCleanupStatus: "active",
          expectedRunId: "run1",
          verifiedRgRunIdTag: "run1",
        },
      ),
    ).toThrow(/Blocked Microsoft\.Resources RG-level mutation/);

    // Backup restore destinations targeting external RGs AND cross-subscription soft-delete purges are blocked (#51060, #51170)!
    expect(() =>
      assertSafeArmTarget(
        "POST",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-arm-blackbox-appconfig-abc123/providers/Microsoft.RecoveryServices/vaults/v1/backupFabrics/Azure/protectionContainers/c1/protectedItems/i1/recoveryPoints/rp1/restore?api-version=2024-04-01`,
        {
          trustedArmBaseUrl: "https://management.azure.com",
          subscriptionId: REAL_SUB_ID,
          disposableRgName: "rg-arm-blackbox-appconfig-abc123",
          disposableRgCleanupStatus: "active",
          expectedRunId: "run1",
          verifiedRgRunIdTag: "run1",
        },
        {
          properties: {
            targetResourceGroupId: `/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-production`,
          },
        },
      ),
    ).toThrow(/Blocked cross-scope mutation field "targetResourceGroupId"/);

    expect(() =>
      assertSafeArmTarget(
        "POST",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/providers/Microsoft.AppConfiguration/locations/eastus/deletedConfigurationStores/bbx-store-01/purge?api-version=2024-06-01`,
        {
          trustedArmBaseUrl: "https://management.azure.com",
          subscriptionId: REAL_SUB_ID,
          disposableRgName: "rg-arm-blackbox-appconfig-abc123",
          disposableRgCleanupStatus: "active",
          expectedRunId: "run1",
          verifiedRgRunIdTag: "run1",
          ownedTargetResources: [
            {
              subscriptionId: "11111111-1111-1111-1111-111111111111",
              providerNamespace: "Microsoft.AppConfiguration",
              collectionSegment: "configurationStores",
              name: "bbx-store-01",
              location: "eastus",
              resourceGroupName: "rg-arm-blackbox-appconfig-abc123",
              resourceId:
                "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/rg-arm-blackbox-appconfig-abc123/providers/Microsoft.AppConfiguration/configurationStores/bbx-store-01",
            },
          ],
        },
      ),
    ).toThrow(/Blocked soft-delete POST on unowned resource/);

    // Literal dots in encoded JSON @secret property names are preserved (#51232)!
    const literalDotSanitized = sanitizePayload(
      { properties: { "opaque.proof": "LITERAL_DOT_SECRET_999" } },
      { extraSecretPropertyPaths: ["properties.opaque\\.proof"] },
    );
    expect(JSON.stringify(literalDotSanitized)).not.toContain("LITERAL_DOT_SECRET_999");
    expect(JSON.stringify(literalDotSanitized)).toContain("<redacted>");

    // stripConfiguredArmBasePath preserves percent-encoded %25 and %2F for single-pass decoding (#60789)!
    expect(
      stripConfiguredArmBasePath(
        `${canaryBaseUrl}/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-arm-blackbox-test/providers/Microsoft.MockWidget/widgets/budget%25`,
        canaryBaseUrl,
      ),
    ).toBe(
      `/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-arm-blackbox-test/providers/Microsoft.MockWidget/widgets/budget%25`,
    );

    // Root whole-body @secret object AND @secret query parameters on URLs are redacted (#60682, #60746)!
    const rootSecretSanitized = sanitizePayload(
      { opaqueMaterial: "ROOT_OBJECT_SECRET_MATERIAL" },
      { extraSecretPropertyPaths: ["parameters"] },
      "parameters",
    );
    expect(JSON.stringify(rootSecretSanitized)).not.toContain("ROOT_OBJECT_SECRET_MATERIAL");
    expect(JSON.stringify(rootSecretSanitized)).toContain("<redacted>");

    const urlSecretSanitized = sanitizePayload(
      "https://management.azure.com/subscriptions/0000/providers/Microsoft.Foo/items?api-version=2025-01-01&opaqueProof=LIVE_SECRET_QUERY_VAL",
      { secretQueryParamNames: ["opaqueProof"] },
    );
    expect(String(urlSecretSanitized)).not.toContain("LIVE_SECRET_QUERY_VAL");
    expect(String(urlSecretSanitized)).toContain("opaqueProof=<redacted>");

    // Aggregating two runs of the same provider + apiVersion keeps distinct serviceIds (#60893)!
    const workDirSecond = path.join(tempRoot, "work-canary-second");
    await discoverSpecInventory({
      specPath: projectDir,
      apiVersion: "2025-01-01",
      workDir: workDirSecond,
      armBaseUrl: canaryBaseUrl,
      subscriptionId: REAL_SUB_ID,
      location: "westus2",
    });
    await buildSummaryReport(workDirSecond, { emitHtml: false });

    const canaryReport = await buildSummaryReport(workDir, { extraWorkDirs: [workDirSecond] });
    expect(canaryReport.report.armBaseUrl).toBe(canaryBaseUrl);
    const canaryDataJs = fs.readFileSync(
      path.join(canaryReport.htmlDir!, "assets", "portal-data.js"),
      "utf8",
    );
    const canaryBundle = JSON.parse(
      fs.readFileSync(path.join(canaryReport.htmlDir!, "assets", "portal-data.json"), "utf8"),
    ) as { services: Array<{ serviceId: string }> };
    expect(canaryBundle.services.length).toBe(2);
    expect(canaryBundle.services[0].serviceId).not.toBe(canaryBundle.services[1].serviceId);
    // Inline script bundle escapes </script> to prevent XSS breakout!
    expect(canaryDataJs).not.toContain("</script>");
    expect(canaryDataJs).toContain("\\u003c/script\\u003e");

    // 3. Verify Step 1 `rg create` -> Step 2 `discover` execution order on a fresh work-dir!
    const workDirRgFirst = path.join(tempRoot, "work-rg-first");
    const createdRgFirst = await createDisposableResourceGroup({
      workDir: workDirRgFirst,
      subscriptionId: REAL_SUB_ID,
      location: "eastus",
      serviceHint: "mockwidget",
      armBaseUrl: canaryBaseUrl,
      allowedArmOrigins: [pollServerUrl],
      bearerToken: MOCK_TOKEN,
    });
    expect(createdRgFirst.rgName).toMatch(/^rg-arm-blackbox-mockwidget-/);

    // Conflicting subscriptionId or armBaseUrl on subsequent `discover` while RG is active is rejected!
    await expect(
      discoverSpecInventory({
        specPath: projectDir,
        apiVersion: "2025-01-01",
        workDir: workDirRgFirst,
        subscriptionId: "00000000-0000-0000-0000-000000000001",
      }),
    ).rejects.toThrow(/Cannot switch subscriptionId/);

    const attachedLedger = await discoverSpecInventory({
      specPath: projectDir,
      apiVersion: "2025-01-01",
      workDir: workDirRgFirst,
    });
    expect(attachedLedger.disposableResourceGroup?.name).toBe(createdRgFirst.rgName);
    expect(attachedLedger.disposableResourceGroup?.cleanupStatus).toBe("active");
    expect(attachedLedger.executionOrder.length).toBeGreaterThan(0);

    const rgFirstProbe = await executeOperationProbe({
      workDir: workDirRgFirst,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Widgets_CreateOrUpdate",
        body: { location: "eastus", properties: { skuTier: "Standard" } },
        pollIntervalMs: 5,
      },
    });
    expect(rgFirstProbe.trace.probeSucceeded).toBe(true);
    await deleteDisposableResourceGroup({ workDir: workDirRgFirst, bearerToken: MOCK_TOKEN });

    // 4. Verify `discover` -> `rg create` honors --arm-token-resource and --allowed-arm-origins without --arm-base-url (#920581)!
    const workDirOverride = path.join(tempRoot, "work-discover-then-rg-overrides");
    await discoverSpecInventory({
      specPath: projectDir,
      apiVersion: "2025-01-01",
      workDir: workDirOverride,
      armBaseUrl: canaryBaseUrl,
      subscriptionId: REAL_SUB_ID,
      location: "eastus",
    });
    await createDisposableResourceGroup({
      workDir: workDirOverride,
      armTokenResource: "api://custom-rg-stage-audience",
      allowedArmOrigins: [pollServerUrl],
      bearerToken: MOCK_TOKEN,
    });
    const overrideLedger = JSON.parse(
      fs.readFileSync(path.join(workDirOverride, "coverage-ledger.json"), "utf8"),
    ) as CoverageLedger;
    expect(overrideLedger.armTokenResource).toBe("api://custom-rg-stage-audience");
    expect(overrideLedger.allowedArmOrigins).toContain(pollServerUrl.toLowerCase());
    await deleteDisposableResourceGroup({ workDir: workDirOverride, bearerToken: MOCK_TOKEN });
  });

  it("enforces pure wire-truth example responses without backfilling un-observed 2xx codes and gates --write-to-spec on OAV completeness", async () => {
    const tempRoot = makeTempDir();
    const projectDir = path.join(
      tempRoot,
      "specification",
      "mockkv",
      "resource-manager",
      "Microsoft.MockKv",
      "MockKv",
    );
    fs.mkdirSync(projectDir, { recursive: true });
    fs.writeFileSync(path.join(projectDir, "tspconfig.yaml"), "{}\n", "utf8");
    fs.writeFileSync(
      path.join(projectDir, "main.tsp"),
      `
import "@typespec/http";
import "@typespec/rest";
import "@typespec/versioning";
import "@azure-tools/typespec-azure-core";
import "@azure-tools/typespec-azure-resource-manager";

using TypeSpec.Http;
using TypeSpec.Rest;
using TypeSpec.Versioning;
using Azure.ResourceManager;

@armProviderNamespace
@service(#{ title: "Microsoft.MockKv" })
@versioned(Versions)
namespace Microsoft.MockKv;

enum Versions {
  @armCommonTypesVersion(Azure.ResourceManager.CommonTypes.Versions.v5)
  v2025_01_01: "2025-01-01",
}

model KvItem is TrackedResource<KvItemProperties> {
  ...ResourceNameParameter<KvItem, "itemName", "items", "^[a-zA-Z0-9-]{3,24}$">;
}

model KvItemProperties {
  value?: string;
  @visibility(Lifecycle.Read)
  provisioningState?: ResourceProvisioningState;
}

model KvItemUpdate {
  properties?: {
    value?: string;
  };
}

@armResourceOperations
interface KvItems {
  get is ArmResourceRead<KvItem>;
  createOrUpdate is ArmResourceCreateOrReplaceAsync<KvItem>;
  update is ArmCustomPatchAsync<KvItem, KvItemUpdate>;
  #suppress "@azure-tools/typespec-azure-resource-manager/arm-delete-operation-response-codes" "Legacy 200|202|204 delete contract"
  delete is ArmResourceDeleteAsync<KvItem>;
  getLogOutput is ArmResourceActionSync<KvItem, void, {
    @statusCode statusCode: 200;
    @header contentType: "text/plain";
    @body output: string;
  }>;
}
`,
      "utf8",
    );

    let mockBaseUrl = "";
    const server = http.createServer((req, res) => {
      const reqUrl = new URL(req.url ?? "/", "http://127.0.0.1");
      const pathname = reqUrl.pathname;
      const method = (req.method ?? "GET").toUpperCase();

      if (/^\/subscriptions\/[^/]+\/resourcegroups\/rg-arm-blackbox-[^/]+$/i.test(pathname)) {
        const rgName = pathname.split("/").pop()!;
        if (method === "PUT" || method === "GET") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              id: pathname,
              name: rgName,
              location: "eastus",
              tags: { "arm-blackbox-ephemeral": "true", "arm-blackbox-run-id": activeRunId },
              properties: { provisioningState: "Succeeded" },
            }),
          );
          return;
        }
        if (method === "DELETE") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({}));
          return;
        }
      }

      if (pathname.endsWith("/asyncOps/put-kv-1") && method === "GET") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ status: "Succeeded" }));
        return;
      }

      if (pathname.includes("/providers/Microsoft.MockKv/items/item-01")) {
        if (method === "PUT") {
          res.writeHead(201, {
            "Content-Type": "application/json",
            "Azure-AsyncOperation": `${mockBaseUrl}/subscriptions/${REAL_SUB_ID}/providers/Microsoft.MockKv/locations/eastus/asyncOps/put-kv-1?api-version=2025-01-01`,
            "Retry-After": "0",
          });
          res.end(
            JSON.stringify({
              id: pathname,
              name: "item-01",
              type: "Microsoft.MockKv/items",
              location: "eastus",
              properties: { value: "v1", provisioningState: "Creating" },
            }),
          );
          return;
        }
        if (method === "GET") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              id: pathname,
              name: "item-01",
              type: "Microsoft.MockKv/items",
              location: "eastus",
              properties: { value: "v1", provisioningState: "Succeeded" },
            }),
          );
          return;
        }
        if (method === "PATCH") {
          // Declared LRO (200 | 202), but completes synchronously with 200!
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              id: pathname,
              name: "item-01",
              type: "Microsoft.MockKv/items",
              location: "eastus",
              properties: { value: "v2", provisioningState: "Succeeded" },
            }),
          );
          return;
        }
        if (pathname.endsWith("/getLogOutput") && method === "POST") {
          res.writeHead(200, { "Content-Type": "text/plain; charset=utf-8" });
          res.end("LOG_LINE_".repeat(200) + "TAIL_MARKER_END");
          return;
        }
        if (method === "DELETE") {
          // Declared LRO (200 | 202 | 204), but completes synchronously with 204 (like KeyValues_Delete)!
          res.writeHead(204);
          res.end();
          return;
        }
      }

      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { code: "NotFound", message: "Not found" } }));
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });
    server.keepAliveTimeout = 60_000;
    servers.push(server);
    mockBaseUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

    const workDir = path.join(tempRoot, "work");
    const inv = await discoverSpecInventory({
      specPath: projectDir,
      apiVersion: "2025-01-01",
      workDir,
      armBaseUrl: mockBaseUrl,
      subscriptionId: REAL_SUB_ID,
      location: "eastus",
    });
    const activeRunId = inv.runId!;

    const { rgName } = await createDisposableResourceGroup({
      workDir,
      bearerToken: MOCK_TOKEN,
    });
    const itemUrl = `/subscriptions/${REAL_SUB_ID}/resourceGroups/${rgName}/providers/Microsoft.MockKv/items/item-01`;

    await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "KvItems_CreateOrUpdate",
        pathOrUrl: itemUrl,
        body: { location: "eastus", properties: { value: "v1" } },
        pollIntervalMs: 5,
      },
    });
    await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "KvItems_Get",
        pathOrUrl: itemUrl,
      },
    });
    const patchProbe = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "KvItems_Update",
        pathOrUrl: itemUrl,
        body: { properties: { value: "v2" } },
      },
    });
    const logProbe = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "KvItems_GetLogOutput",
        pathOrUrl: `${itemUrl}/getLogOutput`,
      },
    });
    expect(logProbe.trace.discrepancies).toEqual([]);
    expect(typeof logProbe.trace.exchanges[0].response.body).toBe("string");
    expect(String(logProbe.trace.exchanges[0].response.body)).toContain("TAIL_MARKER_END");
    expect((logProbe.trace.exchanges[0].response.body as string).length).toBeGreaterThan(1500);

    const delProbe = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "KvItems_Delete",
        pathOrUrl: itemUrl,
      },
    });
    // Synchronous completion of declared LRO produces zero behavioral discrepancies!
    expect(patchProbe.trace.discrepancies).toEqual([]);
    expect(delProbe.trace.discrepancies).toEqual([]);

    // Reject --write-to-spec when TypeSpec schema validation is disabled!
    await expect(
      generateLiveExamples({
        workDir,
        writeToSpec: true,
        validateWithTypeSpec: false,
      }),
    ).rejects.toThrow(/Cannot disable TypeSpec validation/);

    const artifacts = await generateLiveExamples({
      workDir,
      writeToSpec: true,
      validateWithTypeSpec: true,
    });
    expect(artifacts.length).toBe(5);

    // 1. Synchronous 204 DELETE on 200|202|204 contract emits ONLY "204" in scratch and is skipped by --write-to-spec!
    const delArtifact = artifacts.find((a) => a.operationId === "KvItems_Delete")!;
    const delDoc = JSON.parse(fs.readFileSync(delArtifact.scratchPath, "utf8")) as {
      responses: Record<string, unknown>;
    };
    expect(Object.keys(delDoc.responses)).toEqual(["204"]);
    expect(delDoc.responses["202"]).toBeUndefined();
    expect(delDoc.responses["200"]).toBeUndefined();
    expect(delArtifact.oavComplete).toBe(false);
    expect(delArtifact.missingDeclaredStatusCodes).toEqual(["200", "202"]);
    expect(delArtifact.writtenSpecPaths).toEqual([]);
    expect(delArtifact.specWriteSkippedReason).toContain("OAV111");

    // 2. Synchronous 200 PATCH on 200|202 contract emits ONLY "200" in scratch and is skipped by --write-to-spec!
    const patchArtifact = artifacts.find((a) => a.operationId === "KvItems_Update")!;
    const patchDoc = JSON.parse(fs.readFileSync(patchArtifact.scratchPath, "utf8")) as {
      responses: Record<string, unknown>;
    };
    expect(Object.keys(patchDoc.responses)).toEqual(["200"]);
    expect(patchArtifact.oavComplete).toBe(false);
    expect(patchArtifact.writtenSpecPaths).toEqual([]);

    // 3. PUT (201 + final-get 200) and GET (200) covered 100% of declared 2xx codes and WERE promoted to spec!
    const putArtifact = artifacts.find((a) => a.operationId === "KvItems_CreateOrUpdate")!;
    const getArtifact = artifacts.find((a) => a.operationId === "KvItems_Get")!;
    expect(putArtifact.oavComplete).toBe(true);
    expect(putArtifact.writtenSpecPaths.length).toBe(1);
    expect(getArtifact.oavComplete).toBe(true);
    expect(getArtifact.writtenSpecPaths.length).toBe(1);

    const specExamplesDir = path.join(projectDir, "examples", "2025-01-01");
    expect(fs.readdirSync(specExamplesDir).sort()).toEqual([
      "KvItems_CreateOrUpdate.json",
      "KvItems_Get.json",
      "KvItems_GetLogOutput.json",
    ]);
    const logExDoc = JSON.parse(
      fs.readFileSync(path.join(specExamplesDir, "KvItems_GetLogOutput.json"), "utf8"),
    ) as { responses: { "200": { body: string } } };
    expect(logExDoc.responses["200"].body).toContain("TAIL_MARKER_END");

    // 4. Headerless 202 on a declared DELETE/POST/PATCH LRO is flagged by evaluateExampleOavCompleteness (LRO_RESPONSE_HEADER)!
    const headerlessCheck = evaluateExampleOavCompleteness(inv.operations["KvItems_Delete"], {
      responses: { "200": {}, "202": {}, "204": {} },
    });
    expect(headerlessCheck.oavComplete).toBe(false);
    expect(headerlessCheck.oavIssues.some((m) => m.includes("LRO_RESPONSE_HEADER"))).toBe(true);

    // 5. Summary report & HTML portal bundle surface OAV-complete vs wire-subset counts!
    await deleteDisposableResourceGroup({ workDir, bearerToken: MOCK_TOKEN });
    const { report, htmlDir } = await buildSummaryReport(workDir);
    expect(report.exampleSummary.totalGenerated).toBe(5);
    expect(report.exampleSummary.oavComplete).toBe(3);
    expect(report.exampleSummary.wireSubsetIncomplete).toBe(2);
    const portalData = JSON.parse(
      fs.readFileSync(path.join(htmlDir!, "assets", "portal-data.json"), "utf8"),
    ) as {
      portfolioSummary: { totalGeneratedExamples: number; oavCompleteExamples: number };
    };
    expect(portalData.portfolioSummary.totalGeneratedExamples).toBe(5);
    expect(portalData.portfolioSummary.oavCompleteExamples).toBe(3);
    // Atomic writes leave zero residual .tmp files in workDir!
    expect(fs.readdirSync(workDir).some((f) => f.endsWith(".tmp"))).toBe(false);

    // 6. Verify nested external resource IDs (e.g. dataDisks[].managedDisk.id), encoded ?%73%69%67= SAS signatures,
    //    400 error secret sanitization, and validation failure propagation!
    expect(() =>
      assertSafeArmTarget(
        "PUT",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/${rgName}/providers/Microsoft.Compute/virtualMachines/vm1?api-version=2024-07-01`,
        {
          trustedArmBaseUrl: "https://management.azure.com",
          subscriptionId: REAL_SUB_ID,
          disposableRgName: rgName,
          disposableRgCleanupStatus: "active",
          expectedRunId: activeRunId,
          verifiedRgRunIdTag: activeRunId,
        },
        {
          properties: {
            storageProfile: {
              dataDisks: [
                {
                  deleteOption: "Delete",
                  managedDisk: {
                    id: `/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-external-disks/providers/Microsoft.Compute/disks/prod-disk-01`,
                  },
                },
              ],
            },
          },
        },
      ),
    ).toThrow(
      /Blocked cross-scope mutation field "properties\.storageProfile\.dataDisks\[0\]\.managedDisk\.id"/,
    );

    const encodedSigSanitized = String(
      sanitizePayload(
        "https://contoso.blob.core.windows.net/a?%73%69%67=LIVE_SIGNATURE_SECRET",
        {},
      ),
    );
    expect(encodedSigSanitized).not.toContain("LIVE_SIGNATURE_SECRET");
    expect(encodedSigSanitized).toContain("sig=<redacted>");

    const err400Discrepancies = analyzeBehavioralDiscrepancies({
      contract: {
        ...inv.operations["KvItems_CreateOrUpdate"],
        secretProperties: ["error.opaqueProof"],
      },
      expectError: false,
      exchanges: [
        {
          step: "initial",
          timestamp: new Date().toISOString(),
          durationMs: 10,
          request: { method: "PUT", url: "https://management.azure.com/x", headers: {} },
          response: {
            status: 400,
            headers: {},
            body: {
              error: {
                code: "InvalidInput",
                message: "Rejected",
                opaqueProof: "RAW_400_SECRET_PROOF_987",
              },
            },
          },
        },
      ],
      observedLro: { detected: false, detectionSignals: [], pollCount: 0 },
      requestSchemaErrors: [],
      responseSchemaErrors: [],
    });
    expect(JSON.stringify(err400Discrepancies)).not.toContain("RAW_400_SECRET_PROOF_987");
    expect(JSON.stringify(err400Discrepancies)).toContain("<redacted>");

    const failedValidation = await runTypeSpecLiveValidation(
      path.join(tempRoot, "nonexistent-spec-dir"),
      "2025-01-01",
      "KvItems_CreateOrUpdate",
      {
        step: "initial",
        timestamp: new Date().toISOString(),
        durationMs: 1,
        request: { method: "PUT", url: "https://management.azure.com/x", headers: {} },
        response: { status: 400, headers: {} },
      },
    );
    expect(failedValidation.requestErrors.length).toBeGreaterThan(0);
    expect(failedValidation.requestErrors[0].code).toBe("TYPESPEC_VALIDATION_ERROR");

    // Read-only location check*Visibility POSTs are permitted by assertSafeArmTarget!
    expect(() =>
      assertSafeArmTarget(
        "POST",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/providers/Microsoft.Network/locations/eastus/checkPrivateLinkServiceVisibility?api-version=2026-03-01`,
        {
          trustedArmBaseUrl: "https://management.azure.com",
          subscriptionId: REAL_SUB_ID,
          disposableRgName: rgName,
          disposableRgCleanupStatus: "active",
          expectedRunId: activeRunId,
          verifiedRgRunIdTag: activeRunId,
        },
        { privateLinkServiceAlias: "mypls.alias.eastus.azure.privatelinkservice" },
      ),
    ).not.toThrow();
  });

  it("avoids O(k!) OOM on large non-discriminated SubResource hierarchies with mutual cycles and polls >45 LRO attempts by default", async () => {
    const tempRoot = makeTempDir();
    const projectDir = path.join(
      tempRoot,
      "specification",
      "mocknet",
      "resource-manager",
      "Microsoft.MockNet",
      "MockNet",
    );
    fs.mkdirSync(projectDir, { recursive: true });
    fs.writeFileSync(path.join(projectDir, "tspconfig.yaml"), "{}\n", "utf8");

    // Build 30 non-@discriminator SubResourceModel subclasses with mutual cross-references
    // (previously triggered 30! path explosion in plan-inventory.ts and render-html-report.ts).
    const subModels = Array.from({ length: 30 }, (_, idx) => {
      const nextIdx = (idx + 1) % 30;
      const prevIdx = (idx + 29) % 30;
      return `
model SubChild${idx} extends BaseSubResource {
  peerNext?: SubChild${nextIdx};
  peerPrev?: SubChild${prevIdx};
  genericLink?: BaseSubResource;
  anotherLink?: BaseSubResource;
}`;
    }).join("\n");

    fs.writeFileSync(
      path.join(projectDir, "main.tsp"),
      `
import "@typespec/http";
import "@typespec/rest";
import "@typespec/versioning";
import "@azure-tools/typespec-azure-core";
import "@azure-tools/typespec-azure-resource-manager";

using TypeSpec.Http;
using TypeSpec.Rest;
using TypeSpec.Versioning;
using Azure.ResourceManager;

@armProviderNamespace
@service(#{ title: "Microsoft.MockNet" })
@versioned(Versions)
namespace Microsoft.MockNet;

enum Versions {
  @armCommonTypesVersion(Azure.ResourceManager.CommonTypes.Versions.v5)
  v2026_03_01: "2026-03-01",
}

model BaseSubResource {
  id?: string;
}

${subModels}

model Gateway is TrackedResource<GatewayProperties> {
  ...ResourceNameParameter<Gateway, "gatewayName", "gateways", "^[a-zA-Z0-9-]{3,24}$">;
}

model GatewayProperties {
  sub0?: SubChild0;
  subRef?: BaseSubResource;
  @secret
  sharedKey?: string;
  @visibility(Lifecycle.Read)
  provisioningState?: ResourceProvisioningState;
}

@armResourceOperations
interface Gateways {
  get is ArmResourceRead<Gateway>;
  createOrUpdate is ArmResourceCreateOrReplaceAsync<Gateway>;
}
`,
      "utf8",
    );

    let mockBaseUrl = "";
    let pollCounter = 0;
    let activeRunId = "";
    const server = http.createServer((req, res) => {
      const reqUrl = new URL(req.url ?? "/", "http://127.0.0.1");
      const pathname = reqUrl.pathname;
      const method = (req.method ?? "GET").toUpperCase();

      if (/^\/subscriptions\/[^/]+\/resourcegroups\/rg-arm-blackbox-[^/]+$/i.test(pathname)) {
        const name = pathname.split("/").pop()!;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            id: pathname,
            name,
            location: "eastus",
            tags: { "arm-blackbox-ephemeral": "true", "arm-blackbox-run-id": activeRunId },
            properties: { provisioningState: "Succeeded" },
          }),
        );
        return;
      }

      if (pathname.endsWith("/asyncOps/gw-slow-50") && method === "GET") {
        pollCounter++;
        // Require 50 polls (> old 45-poll ceiling!) before succeeding!
        const status = pollCounter >= 50 ? "Succeeded" : "Updating";
        res.writeHead(200, { "Content-Type": "application/json", "Retry-After": "0" });
        res.end(JSON.stringify({ status }));
        return;
      }

      if (pathname.includes("/providers/Microsoft.MockNet/gateways/gw-01")) {
        if (method === "PUT") {
          res.writeHead(201, {
            "Content-Type": "application/json",
            "Azure-AsyncOperation": `${mockBaseUrl}/subscriptions/${REAL_SUB_ID}/providers/Microsoft.MockNet/locations/eastus/asyncOps/gw-slow-50?api-version=2026-03-01`,
            "Retry-After": "0",
          });
          res.end(
            JSON.stringify({
              id: pathname,
              name: "gw-01",
              type: "Microsoft.MockNet/gateways",
              location: "eastus",
              properties: { provisioningState: "Creating" },
            }),
          );
          return;
        }
        if (method === "GET") {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify({
              id: pathname,
              name: "gw-01",
              type: "Microsoft.MockNet/gateways",
              location: "eastus",
              properties: { provisioningState: "Succeeded" },
            }),
          );
          return;
        }
      }

      res.writeHead(404, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ error: { code: "NotFound", message: "Not found" } }));
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });
    server.keepAliveTimeout = 60_000;
    servers.push(server);
    mockBaseUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

    const workDir = path.join(tempRoot, "work-oom-uncapped");
    const inv = await discoverSpecInventory({
      specPath: projectDir,
      apiVersion: "2026-03-01",
      workDir,
      armBaseUrl: mockBaseUrl,
      subscriptionId: REAL_SUB_ID,
      location: "eastus",
    });
    activeRunId = inv.runId!;
    // @secret inside GatewayProperties is still discovered accurately!
    expect(inv.operations["Gateways_CreateOrUpdate"].secretProperties).toContain(
      "properties.sharedKey",
    );

    const { rgName } = await createDisposableResourceGroup({
      workDir,
      bearerToken: MOCK_TOKEN,
    });
    const gwProbe = await executeOperationProbe({
      workDir,
      bearerToken: MOCK_TOKEN,
      input: {
        operationId: "Gateways_CreateOrUpdate",
        pathOrUrl: `/subscriptions/${REAL_SUB_ID}/resourceGroups/${rgName}/providers/Microsoft.MockNet/gateways/gw-01`,
        body: { location: "eastus", properties: { sharedKey: "SUPER_SECRET_GW_KEY" } },
        pollIntervalMs: 1,
      },
    });
    expect(gwProbe.trace.probeSucceeded).toBe(true);
    expect(gwProbe.trace.observedLro.pollCount).toBe(50);
    expect(gwProbe.trace.observedLro.completionStatus).toBe("succeeded");

    await deleteDisposableResourceGroup({
      workDir,
      bearerToken: MOCK_TOKEN,
      wait: true,
      pollIntervalMs: 1,
      maxPollAttempts: 2,
    });
    const { htmlIndexPath } = await buildSummaryReport(workDir);
    expect(fs.existsSync(htmlIndexPath!)).toBe(true);
  });

  it("enforces intra-RP SubResource DAG ordering, sharding/merging, custom fixtures, warm probe-batch, sync-200 LRO skip, async-202 expectError, and pending===0 RG delete gate", async () => {
    const tempRoot = makeTempDir();
    const projectDir = path.join(tempRoot, "NetGraph.Management");
    fs.mkdirSync(projectDir, { recursive: true });
    fs.writeFileSync(path.join(projectDir, "tspconfig.yaml"), "{}\n", "utf8");

    const tsp = `
import "@typespec/http";
import "@typespec/rest";
import "@typespec/versioning";
import "@typespec/openapi";
import "@azure-tools/typespec-azure-core";

using TypeSpec.Http;
using TypeSpec.Rest;
using TypeSpec.Versioning;
using TypeSpec.OpenAPI;
using Azure.Core;

@service(#{ title: "Microsoft.NetGraph" })
@versioned(Versions)
namespace Microsoft.NetGraph;

enum Versions {
  v2026_03_01: "2026-03-01",
}

model ArmError {
  code: string;
  message: string;
}

@error
model ErrorEnvelope {
  error: ArmError;
}

model SubResourceRef {
  id?: string;
}

model SubnetProps {
  addressPrefix?: string;
  @visibility(Lifecycle.Read)
  provisioningState?: string;
}

model Subnet {
  id?: string;
  name?: string;
  properties?: SubnetProps;
}

model VNetProps {
  subnets?: Subnet[];
  @visibility(Lifecycle.Read)
  provisioningState?: string;
}

model VirtualNetwork {
  @visibility(Lifecycle.Read) id?: string;
  @visibility(Lifecycle.Read) name?: string;
  location: string;
  properties?: VNetProps;
}

model PipProps {
  @visibility(Lifecycle.Read)
  provisioningState?: string;
}

model PublicIPAddress {
  @visibility(Lifecycle.Read) id?: string;
  @visibility(Lifecycle.Read) name?: string;
  location: string;
  properties?: PipProps;
}

model NicProps {
  subnet?: SubResourceRef;
  publicIPAddress?: SubResourceRef;
  keyVaultSecretId?: armResourceIdentifier<[{ type: "Microsoft.KeyVault/vaults" }]>;
  @visibility(Lifecycle.Read)
  provisioningState?: string;
}

model NetworkInterface {
  @visibility(Lifecycle.Read) id?: string;
  @visibility(Lifecycle.Read) name?: string;
  location: string;
  properties?: NicProps;
}

model OpList {
  value: Record<unknown>[];
}

// Provider/Location preflight discovery ops
@route("/providers/Microsoft.NetGraph/operations")
@get
@operationId("Operations_List")
op listOps(@query("api-version") apiVersion: string): OpList | ErrorEnvelope;

@route("/subscriptions/{subscriptionId}/providers/Microsoft.NetGraph/locations/{location}/usages")
@get
@operationId("Usages_List")
op listUsages(
  @path subscriptionId: string,
  @path location: string,
  @query("api-version") apiVersion: string,
): OpList | ErrorEnvelope;

@route("/subscriptions/{subscriptionId}/providers/Microsoft.NetGraph/locations/{location}/checkDnsNameAvailability")
@get
@operationId("CheckDnsNameAvailability")
op checkDns(
  @path subscriptionId: string,
  @path location: string,
  @query domainNameLabel: string,
  @query("api-version") apiVersion: string,
): Record<unknown> | ErrorEnvelope;

@route("/subscriptions/{subscriptionId}/providers/Microsoft.NetGraph/locations/{location}/checkPrivateLinkServiceVisibility")
@post
@operationId("PrivateLinkServices_CheckVisibility")
op checkVisibility(
  @path subscriptionId: string,
  @path location: string,
  @query("api-version") apiVersion: string,
  @body body: Record<unknown>,
): Record<unknown> | ErrorEnvelope;

// VirtualNetworks + Subnets + Instance checkIpAddressAvailability
@route("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetGraph/virtualNetworks/{virtualNetworkName}")
@put
@extension("x-ms-long-running-operation", true)
@operationId("VirtualNetworks_CreateOrUpdate")
op putVnet(
  @path subscriptionId: string,
  @path resourceGroupName: string,
  @path virtualNetworkName: string,
  @query("api-version") apiVersion: string,
  @body parameters: VirtualNetwork,
): VirtualNetwork | ErrorEnvelope;

@route("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetGraph/virtualNetworks/{virtualNetworkName}/checkIpAddressAvailability")
@get
@operationId("VirtualNetworks_CheckIPAddressAvailability")
op checkVnetIp(
  @path subscriptionId: string,
  @path resourceGroupName: string,
  @path virtualNetworkName: string,
  @query ipAddress: string,
  @query("api-version") apiVersion: string,
): Record<unknown> | ErrorEnvelope;

@route("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetGraph/virtualNetworks/{virtualNetworkName}/listDdosProtectionStatus")
@post
@extension("x-ms-long-running-operation", true)
@operationId("VirtualNetworks_ListDdosProtectionStatus")
op listDdos(
  @path subscriptionId: string,
  @path resourceGroupName: string,
  @path virtualNetworkName: string,
  @query("api-version") apiVersion: string,
): { @statusCode _: 202; @header("Location") location?: string; } | OpList | ErrorEnvelope;

@route("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetGraph/virtualNetworks/{virtualNetworkName}")
@delete
@operationId("VirtualNetworks_Delete")
op deleteVnet(
  @path subscriptionId: string,
  @path resourceGroupName: string,
  @path virtualNetworkName: string,
  @query("api-version") apiVersion: string,
): { @statusCode _: 200 } | { @statusCode _: 204 } | ErrorEnvelope;

@route("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetGraph/virtualNetworks/{virtualNetworkName}/subnets/{subnetName}")
@put
@operationId("Subnets_CreateOrUpdate")
op putSubnet(
  @path subscriptionId: string,
  @path resourceGroupName: string,
  @path virtualNetworkName: string,
  @path subnetName: string,
  @query("api-version") apiVersion: string,
  @body subnetParameters: Subnet,
): Subnet | ErrorEnvelope;

@route("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetGraph/virtualNetworks/{virtualNetworkName}/subnets/{subnetName}")
@delete
@operationId("Subnets_Delete")
op deleteSubnet(
  @path subscriptionId: string,
  @path resourceGroupName: string,
  @path virtualNetworkName: string,
  @path subnetName: string,
  @query("api-version") apiVersion: string,
): { @statusCode _: 200 } | { @statusCode _: 204 } | ErrorEnvelope;

// PublicIPAddresses
@route("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetGraph/publicIPAddresses/{publicIpAddressName}")
@put
@operationId("PublicIPAddresses_CreateOrUpdate")
op putPip(
  @path subscriptionId: string,
  @path resourceGroupName: string,
  @path publicIpAddressName: string,
  @query("api-version") apiVersion: string,
  @body parameters: PublicIPAddress,
): PublicIPAddress | ErrorEnvelope;

@route("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetGraph/publicIPAddresses/{publicIpAddressName}")
@delete
@operationId("PublicIPAddresses_Delete")
op deletePip(
  @path subscriptionId: string,
  @path resourceGroupName: string,
  @path publicIpAddressName: string,
  @query("api-version") apiVersion: string,
): { @statusCode _: 200 } | { @statusCode _: 204 } | ErrorEnvelope;

// NetworkInterfaces referencing BOTH Subnet and PublicIPAddress (intra-RP SubResource refs!)
@route("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetGraph/networkInterfaces/{networkInterfaceName}")
@put
@operationId("NetworkInterfaces_CreateOrUpdate")
op putNic(
  @path subscriptionId: string,
  @path resourceGroupName: string,
  @path networkInterfaceName: string,
  @query("api-version") apiVersion: string,
  @body parameters: NetworkInterface,
): NetworkInterface | ErrorEnvelope;

@route("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.NetGraph/networkInterfaces/{networkInterfaceName}")
@delete
@operationId("NetworkInterfaces_Delete")
op deleteNic(
  @path subscriptionId: string,
  @path resourceGroupName: string,
  @path networkInterfaceName: string,
  @query("api-version") apiVersion: string,
): { @statusCode _: 200 } | { @statusCode _: 204 } | ErrorEnvelope;

// Cross-RP host route (Microsoft.Compute/cloudServices)
@route("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/cloudServices/{cloudServiceName}/networkInterfaces")
@get
@operationId("NetworkInterfaces_ListCloudServiceNetworkInterfaces")
op listCloudServiceNics(
  @path subscriptionId: string,
  @path resourceGroupName: string,
  @path cloudServiceName: string,
  @query("api-version") apiVersion: string,
): OpList | ErrorEnvelope;
`;
    fs.writeFileSync(path.join(projectDir, "main.tsp"), tsp, "utf8");

    const rgStore = new Map<string, Record<string, unknown>>();
    const customKvStore = new Map<string, Record<string, unknown>>();
    let bogusMonitorPolled = false;
    let baseUrl = "";

    const server = http.createServer((req, res) => {
      const reqUrl = new URL(req.url ?? "/", "http://127.0.0.1");
      const pathname = reqUrl.pathname;
      const method = req.method ?? "GET";

      const rgMatch = /^\/subscriptions\/([^/]+)\/resourceGroups\/([^/]+)$/i.exec(pathname);
      if (rgMatch) {
        const key = `${rgMatch[1].toLowerCase()}/${rgMatch[2].toLowerCase()}`;
        if (method === "GET") {
          const found = rgStore.get(key);
          res.writeHead(found ? 200 : 404, { "Content-Type": "application/json" });
          res.end(JSON.stringify(found ?? { error: { code: "NotFound", message: "missing" } }));
          return;
        }
        if (method === "PUT") {
          let raw = "";
          req.on("data", (c: Buffer) => (raw += String(c)));
          req.on("end", () => {
            const parsed = (raw ? JSON.parse(raw) : {}) as Record<string, unknown>;
            const rec = { id: pathname, location: "eastus2", ...parsed };
            rgStore.set(key, rec);
            res.writeHead(201, { "Content-Type": "application/json" });
            res.end(JSON.stringify(rec));
          });
          return;
        }
        if (method === "DELETE") {
          rgStore.delete(key);
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ id: pathname }));
          return;
        }
      }

      // Custom KeyVault fixture endpoint
      if (pathname.includes("/providers/Microsoft.KeyVault/vaults/")) {
        if (method === "PUT") {
          let raw = "";
          req.on("data", (c: Buffer) => (raw += String(c)));
          req.on("end", () => {
            const parsed = (raw ? JSON.parse(raw) : {}) as Record<string, unknown>;
            const rec = {
              id: pathname,
              location: "eastus2",
              ...parsed,
              properties: { provisioningState: "Succeeded" },
            };
            customKvStore.set(pathname.toLowerCase(), rec);
            res.writeHead(200, {
              "Content-Type": "application/json",
              // Stale async header on sync 200 Succeeded (must NOT be polled!)
              "Azure-AsyncOperation": `${baseUrl}/bogus-404-monitor`,
            });
            res.end(JSON.stringify(rec));
          });
          return;
        }
        if (method === "GET") {
          const rec = customKvStore.get(pathname.toLowerCase());
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(
            JSON.stringify(rec ?? { id: pathname, properties: { provisioningState: "Succeeded" } }),
          );
          return;
        }
      }

      if (pathname === "/bogus-404-monitor") {
        bogusMonitorPolled = true;
        res.writeHead(404, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ error: { code: "NotFound", message: "stale async op" } }));
        return;
      }

      // Async 202 expectError endpoint (VirtualNetworks_ListDdosProtectionStatus)
      if (pathname.endsWith("/listDdosProtectionStatus") && method === "POST") {
        res.writeHead(202, {
          "Content-Type": "application/json",
          Location: `${baseUrl}/ddos-op-fail`,
          "Retry-After": "0",
        });
        res.end();
        return;
      }
      if (pathname === "/ddos-op-fail") {
        res.writeHead(400, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: {
              code: "VirtualNetworkBasicDdosProtectionNotEnabled",
              message: "DDoS protection is not enabled on this VNet.",
            },
          }),
        );
        return;
      }

      // VNet PUT returns HTTP 200 with provisioningState: "Succeeded" AND a stale 404 Azure-AsyncOperation header!
      if (
        /\/providers\/Microsoft\.NetGraph\/virtualNetworks\/[^/]+$/i.test(pathname) &&
        method === "PUT"
      ) {
        res.writeHead(200, {
          "Content-Type": "application/json",
          "Azure-AsyncOperation": `${baseUrl}/bogus-404-monitor`,
        });
        res.end(
          JSON.stringify({
            id: pathname,
            name: pathname.split("/").pop(),
            location: "eastus2",
            properties: { provisioningState: "Succeeded" },
          }),
        );
        return;
      }

      // Generic 200 responses for other NetGraph endpoints
      if (method === "DELETE") {
        res.writeHead(204);
        res.end();
        return;
      }
      if (
        pathname.endsWith("/operations") ||
        pathname.endsWith("/usages") ||
        pathname.endsWith("/networkInterfaces")
      ) {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ value: [] }));
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(
        JSON.stringify({
          id: pathname,
          name: pathname.split("/").pop(),
          location: "eastus2",
          properties: { provisioningState: "Succeeded" },
        }),
      );
    });

    await new Promise<void>((resolve) => {
      server.listen(0, "127.0.0.1", () => resolve());
    });
    server.keepAliveTimeout = 60_000;
    servers.push(server);
    baseUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;

    {
      const workDir = path.join(tempRoot, "netgraph-work");
      const ledger = await discoverSpecInventory({
        specPath: projectDir,
        apiVersion: "2026-03-01",
        workDir,
        armBaseUrl: baseUrl,
        subscriptionId: REAL_SUB_ID,
        location: "eastus2",
      });

      // 1. Scope-aware preflight-discovery classification (Gap 3):
      expect(ledger.operations.Operations_List.phase).toBe("preflight-discovery");
      expect(ledger.operations.Usages_List.phase).toBe("preflight-discovery");
      expect(ledger.operations.CheckDnsNameAvailability.phase).toBe("preflight-discovery");
      expect(ledger.operations.PrivateLinkServices_CheckVisibility.phase).toBe(
        "preflight-discovery",
      );
      // Instance checkIpAddressAvailability MUST NOT be preflight-discovery — it must run AFTER VNet create!
      expect(ledger.operations.VirtualNetworks_CheckIPAddressAvailability.phase).not.toBe(
        "preflight-discovery",
      );

      // 2. Clean externalDependencies (no self-RP leaf noise; KeyVault + Compute host scope retained):
      expect(
        ledger.externalDependencies.some((d) => d.providerNamespace === "Microsoft.NetGraph"),
      ).toBe(false);
      expect(
        ledger.externalDependencies.some((d) => d.providerNamespace === "Microsoft.KeyVault"),
      ).toBe(true);
      expect(
        ledger.externalDependencies.some((d) => d.providerNamespace === "Microsoft.Compute"),
      ).toBe(true);

      // 3. Intra-RP SubResource DAG ordering (Gap 1 & Gap 5):
      expect(ledger.operations.NetworkInterfaces_CreateOrUpdate.intraRpDependencies).toEqual([
        "Microsoft.NetGraph/publicIPAddresses",
        "Microsoft.NetGraph/virtualNetworks/subnets",
      ]);
      // Inline child array VirtualNetwork.properties.subnets must NOT make VirtualNetwork depend on Subnets!
      expect(ledger.operations.VirtualNetworks_CreateOrUpdate.intraRpDependencies).toBeUndefined();

      const order = ledger.executionOrder;
      expect(order.indexOf("VirtualNetworks_CreateOrUpdate")).toBeLessThan(
        order.indexOf("Subnets_CreateOrUpdate"),
      );
      expect(order.indexOf("Subnets_CreateOrUpdate")).toBeLessThan(
        order.indexOf("NetworkInterfaces_CreateOrUpdate"),
      );
      expect(order.indexOf("PublicIPAddresses_CreateOrUpdate")).toBeLessThan(
        order.indexOf("NetworkInterfaces_CreateOrUpdate"),
      );
      // Reverse bottom-up delete order: NIC deleted BEFORE Subnet and PublicIP, Subnet deleted BEFORE VNet!
      expect(order.indexOf("NetworkInterfaces_Delete")).toBeLessThan(
        order.indexOf("Subnets_Delete"),
      );
      expect(order.indexOf("NetworkInterfaces_Delete")).toBeLessThan(
        order.indexOf("PublicIPAddresses_Delete"),
      );
      expect(order.indexOf("Subnets_Delete")).toBeLessThan(order.indexOf("VirtualNetworks_Delete"));
      expect(
        ledger.executionGraph?.edges.some(
          (e) =>
            e.from === "Subnets_CreateOrUpdate" &&
            e.to === "NetworkInterfaces_CreateOrUpdate" &&
            e.reason === "intra-rp-resource-ref",
        ),
      ).toBe(true);

      // 4. --resource-filter automatically closes over transitive intra-RP create/delete prerequisites:
      const filteredDir = path.join(tempRoot, "netgraph-filtered");
      const filteredLedger = await discoverSpecInventory({
        specPath: projectDir,
        apiVersion: "2026-03-01",
        workDir: filteredDir,
        armBaseUrl: baseUrl,
        subscriptionId: REAL_SUB_ID,
        location: "eastus2",
        resourceFilter: ["NetworkInterfaces_CreateOrUpdate"],
      });
      expect(Object.keys(filteredLedger.operations)).toEqual(
        expect.arrayContaining([
          "VirtualNetworks_CreateOrUpdate",
          "Subnets_CreateOrUpdate",
          "PublicIPAddresses_CreateOrUpdate",
          "NetworkInterfaces_CreateOrUpdate",
          "Subnets_Delete",
          "PublicIPAddresses_Delete",
          "VirtualNetworks_Delete",
        ]),
      );

      // 5. Sharding & execution across shards + custom fixture + sync-200 LRO skip + async-202 expectError + pending===0 gate:
      const manifest = partitionLedgerIntoShards({
        workDir,
        shardCount: 2,
        maxOpsPerShard: 10,
      });
      expect(manifest.shardCount).toBe(2);
      const unionShardOps = new Set<string>();
      for (const s of manifest.shards) {
        const sLedger = JSON.parse(
          fs.readFileSync(path.join(s.workDir, "coverage-ledger.json"), "utf8"),
        ) as CoverageLedger;
        for (const opId of Object.keys(sLedger.coverage)) {
          unionShardOps.add(opId);
        }
      }
      expect(unionShardOps.size).toBe(ledger.executionOrder.length);

      // Execute each shard to pending === 0!
      for (const shard of manifest.shards) {
        await createDisposableResourceGroup({
          workDir: shard.workDir,
          bearerToken: MOCK_TOKEN,
        });

        // CLI `rg delete` refuses teardown while operations are still pending (Gap 6)!
        await expect(runCli(["rg", "delete", "--work-dir", shard.workDir])).rejects.toThrow(
          /remain "pending"/,
        );

        // Test custom cross-RP fixture inside disposable RG (Gap 2) + cross-RG escape block!
        await expect(
          provisionExternalFixture({
            workDir: shard.workDir,
            kind: "custom",
            customResourcePath: `/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-prod-escape/providers/Microsoft.KeyVault/vaults/kvbad`,
            customApiVersion: "2023-07-01",
            bearerToken: MOCK_TOKEN,
          }),
        ).rejects.toThrow(/Blocked custom fixture/);

        const kvFix = await provisionExternalFixture({
          workDir: shard.workDir,
          kind: "custom",
          customResourcePath: "providers/Microsoft.KeyVault/vaults/bbxkvtest",
          customApiVersion: "2023-07-01",
          customBody: { properties: { sku: { family: "A", name: "standard" } } },
          bearerToken: MOCK_TOKEN,
        });
        expect(kvFix.resourceId).toContain("/providers/Microsoft.KeyVault/vaults/bbxkvtest");

        const sLedger = JSON.parse(
          fs.readFileSync(path.join(shard.workDir, "coverage-ledger.json"), "utf8"),
        ) as CoverageLedger;

        const batchItems: Parameters<typeof executeProbeBatch>[0]["items"] = [];
        for (const opId of sLedger.executionOrder) {
          if (opId === "NetworkInterfaces_ListCloudServiceNetworkInterfaces") {
            batchItems.push({
              markBlocked: {
                operationIds: [opId],
                reason: "Hosted under retired Microsoft.Compute/cloudServices (classic)",
              },
            });
          } else if (opId === "VirtualNetworks_ListDdosProtectionStatus") {
            // Test async HTTP 202 polling on expectError: true (Gap 9)!
            batchItems.push({
              operationId: opId,
              expectError: true,
              scenario: "ddos-not-enabled",
              pollIntervalMs: 1,
            });
            // Then mark blocked due to DDoS plan requirement
            batchItems.push({
              markBlocked: {
                operationIds: [opId],
                reason:
                  "Requires paid DDoS Protection Plan on VNet (live 400 VirtualNetworkBasicDdosProtectionNotEnabled)",
              },
            });
          } else if (opId === "CheckDnsNameAvailability") {
            batchItems.push({
              operationId: opId,
              query: { domainNameLabel: "bbxdnstest" },
            });
          } else if (opId === "VirtualNetworks_CheckIPAddressAvailability") {
            batchItems.push({
              operationId: opId,
              query: { ipAddress: "10.0.0.4" },
            });
          } else if (opId === "PrivateLinkServices_CheckVisibility") {
            batchItems.push({
              operationId: opId,
              body: { privateLinkServiceAlias: "test.alias.eastus2.azure.privatelinkservice" },
            });
          } else if (opId.endsWith("_CreateOrUpdate")) {
            batchItems.push({
              operationId: opId,
              body:
                opId === "Subnets_CreateOrUpdate"
                  ? { properties: { addressPrefix: "10.0.0.0/24" } }
                  : { location: "eastus2", properties: {} },
            });
          } else {
            batchItems.push({ operationId: opId });
          }
        }

        const results = await executeProbeBatch({
          workDir: shard.workDir,
          items: batchItems,
          continueOnError: false,
          bearerToken: MOCK_TOKEN,
        });
        expect(results.every((r) => r.probeSucceeded)).toBe(true);
        // Stale Azure-AsyncOperation header on HTTP 200 Succeeded must NEVER be polled (Gap 9)!
        expect(bogusMonitorPolled).toBe(false);

        await generateLiveExamples({ workDir: shard.workDir, validateWithTypeSpec: true });

        // Refuses merge while shard RG is still active!
        if (shard === manifest.shards[0]) {
          expect(() => mergeShardWorkDirs({ parentWorkDir: workDir })).toThrow(
            /Refusing to merge shard/,
          );
        }

        await deleteDisposableResourceGroup({
          workDir: shard.workDir,
          wait: true,
          bearerToken: MOCK_TOKEN,
        });
      }

      // 6. Merge shards back into parent workDir and verify pending === 0 across all 15 operations!
      const merged = mergeShardWorkDirs({ parentWorkDir: workDir });
      expect(merged.pendingOperations).toBe(0);
      expect(merged.totalOperations).toBe(ledger.executionOrder.length);
      expect(merged.mergedTraces).toBeGreaterThanOrEqual(13);

      // 7. Concurrent atomic ledger updates preserve both mutations (Gap 8):
      updateLedgerAtomically(workDir, (l) => {
        l.runtimeState!.pathSlotValues.concurrentSlotA = "valA";
      });
      updateLedgerAtomically(workDir, (l) => {
        l.runtimeState!.pathSlotValues.concurrentSlotB = "valB";
      });
      const finalParent = JSON.parse(
        fs.readFileSync(path.join(workDir, "coverage-ledger.json"), "utf8"),
      ) as CoverageLedger;
      expect(finalParent.runtimeState?.pathSlotValues.concurrentSlotA).toBe("valA");
      expect(finalParent.runtimeState?.pathSlotValues.concurrentSlotB).toBe("valB");
    }
  });
});
