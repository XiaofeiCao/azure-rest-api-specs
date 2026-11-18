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
} from "../scripts/manage-rg.ts";
import { discoverSpecInventory } from "../scripts/plan-inventory.ts";
import { buildSummaryReport } from "../scripts/render-report.ts";
import { sanitizePayload } from "../scripts/sanitize-example.ts";
import { DISCREPANCY_RULES } from "../scripts/types.ts";

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

  it("enforces disposable Resource Group write guardrails strictly", () => {
    const ctx = {
      disposableRgName: "rg-arm-blackbox-appconfig-abc123",
      ownedResourceNames: ["bbx-store-01"],
      allowDisposableRgLifecycle: false,
    };

    // Read-only calls anywhere are permitted.
    expect(() =>
      assertSafeArmTarget(
        "GET",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-prod/providers/Microsoft.AppConfiguration/configurationStores?api-version=2024-06-01`,
        ctx,
      ),
    ).not.toThrow();

    // Non-destructive checkNameAvailability POST is permitted.
    expect(() =>
      assertSafeArmTarget(
        "POST",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/providers/Microsoft.AppConfiguration/checkNameAvailability?api-version=2024-06-01`,
        ctx,
      ),
    ).not.toThrow();

    // Mutations inside the disposable RG are permitted.
    expect(() =>
      assertSafeArmTarget(
        "PUT",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-arm-blackbox-appconfig-abc123/providers/Microsoft.AppConfiguration/configurationStores/bbx-store-01?api-version=2024-06-01`,
        ctx,
      ),
    ).not.toThrow();

    // Soft-delete purge of an owned test resource is permitted, but blocked for non-owned resources!
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
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/providers/Microsoft.AppConfiguration/locations/eastus/deletedConfigurationStores/customer-prod-store/purge?api-version=2024-06-01`,
        ctx,
      ),
    ).toThrow(/Blocked mutating POST/);

    // Mutations targeting another RG are blocked!
    expect(() =>
      assertSafeArmTarget(
        "DELETE",
        `https://management.azure.com/subscriptions/${REAL_SUB_ID}/resourceGroups/rg-production/providers/Microsoft.AppConfiguration/configurationStores/prod?api-version=2024-06-01`,
        ctx,
      ),
    ).toThrow(/strictly confined/);
  });

  it("compiles real Microsoft.AppConfiguration TypeSpec in-memory and builds a parent-child-delete-purge DAG with .tsp:line provenance", async () => {
    const workDir = makeTempDir();
    const repoRoot = path.resolve(import.meta.dirname, "../../../..");
    const appConfigSpec = path.join(
      repoRoot,
      "specification",
      "appconfiguration",
      "resource-manager",
      "Microsoft.AppConfiguration",
      "AppConfiguration",
    );

    const ledger = await discoverSpecInventory({
      specPath: appConfigSpec,
      apiVersion: "2025-06-01-preview",
      workDir,
    });

    expect(ledger.providerNamespace).toBe("Microsoft.AppConfiguration");
    expect(ledger.apiVersion).toBe("2025-06-01-preview");
    expect(ledger.availableApiVersions).toContain("2025-06-01-preview");
    expect(ledger.operations.ConfigurationStores_Create.sourceLocation?.file).toMatch(
      /ConfigurationStore\.tsp$/,
    );
    expect(ledger.executionOrder.length).toBe(29);

    const idxOpsList = ledger.executionOrder.indexOf("Operations_List");
    const idxStoreCreate = ledger.executionOrder.indexOf("ConfigurationStores_Create");
    const idxKeyValCreate = ledger.executionOrder.indexOf("KeyValues_CreateOrUpdate");
    const idxKeyValDelete = ledger.executionOrder.indexOf("KeyValues_Delete");
    const idxStoreDelete = ledger.executionOrder.indexOf("ConfigurationStores_Delete");
    const idxPurgeDeleted = ledger.executionOrder.indexOf("ConfigurationStores_PurgeDeleted");

    expect(idxOpsList).toBeGreaterThanOrEqual(0);
    expect(idxPurgeDeleted).toBeGreaterThanOrEqual(0);
    expect(idxOpsList).toBeLessThan(idxStoreCreate);
    expect(idxStoreCreate).toBeLessThan(idxKeyValCreate);
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

    const server = http.createServer((req, res) => {
      const reqUrl = new URL(req.url ?? "/", baseUrl);
      const pathname = reqUrl.pathname;
      const method = req.method?.toUpperCase() ?? "GET";

      // Disposable RG create / delete.
      if (
        /^\/subscriptions\/[^/]+\/resourcegroups\/rg-arm-blackbox-/i.test(pathname) &&
        !pathname.includes("/providers/")
      ) {
        res.writeHead(method === "DELETE" ? 200 : 201, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ id: pathname, location: "eastus" }));
        return;
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
});
