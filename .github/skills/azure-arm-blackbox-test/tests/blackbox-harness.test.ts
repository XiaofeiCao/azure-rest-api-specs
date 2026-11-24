import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as http from "node:http";
import * as path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { assertSafeArmTarget } from "../scripts/auth-and-http.ts";
import { executeOperationProbe } from "../scripts/execute-probe.ts";
import { generateLiveExamples } from "../scripts/generate-examples.ts";
import {
  createDisposableResourceGroup,
  deleteDisposableResourceGroup,
  provisionExternalFixture,
} from "../scripts/manage-rg.ts";
import { discoverSpecInventory } from "../scripts/plan-inventory.ts";
import { buildSummaryReport } from "../scripts/render-report.ts";
import { sanitizePayload } from "../scripts/sanitize-example.ts";
import { DISCREPANCY_RULES, type CoverageLedger } from "../scripts/types.ts";

const REAL_SUB_ID = "87654321-4321-4321-4321-210987654321";
const MOCK_TOKEN = "mock-bearer-token-value";

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

    // Cross-scope RG moveResources and external body targetResourceGroup are blocked (#3904)!
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

    // Verify nested 2D array secret paths (credentials[][].value) AND dotted/empty dictionary keys (#4080, #7984)!
    const dictSanitized = sanitizePayload(
      {
        credentials: {
          "dotted.key.name": { value: "DOTTED_KEY_SECRET_123" },
          "": { value: "EMPTY_KEY_SECRET_456" },
        },
        matrix: [[{ secretTokenVal: "MATRIX_2D_SECRET_789" }]],
      },
      { extraSecretPropertyPaths: ["credentials.*.value", "matrix[][].secretTokenVal"] },
    ) as {
      credentials: Record<string, { value: string }>;
      matrix: Array<Array<{ secretTokenVal: string }>>;
    };
    expect(dictSanitized.credentials["dotted.key.name"].value).toBe("<redacted>");
    expect(dictSanitized.credentials[""].value).toBe("<redacted>");
    expect(dictSanitized.matrix[0][0].secretTokenVal).toBe("<redacted>");

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
  });
});
