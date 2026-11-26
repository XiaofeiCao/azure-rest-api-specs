---
name: azure-arm-blackbox-test
description: 'Blackbox test Azure Resource Manager (ARM) TypeSpec specifications against live deployed Azure service behavior for a target api-version, drive stateful CRUD/action lifecycle probes toward 100% API coverage, detect wire-level discrepancies (such as undeclared LROs, missing polling headers, final-state-via mismatches, schema/mutability/paging drift) with exact .tsp:line provenance, and generate sanitized real-life TypeSpec examples. WHEN: "blackbox test ARM TypeSpec", "validate TypeSpec against live Azure service", "check if live service behavior matches TypeSpec", "detect undeclared LRO in live service", "generate live TypeSpec examples from real ARM service", "100% live API coverage test". DO NOT USE FOR: Swagger/OpenAPI-only specs without TypeSpec, editing or fixing TypeSpec (.tsp) definitions, static-only PR linting without live or recorded HTTP probing, data-plane-only custom auth APIs, or SDK package releases.'
license: MIT
metadata:
  author: Microsoft
  version: "0.2.0-typespec-native"
---

# Azure ARM TypeSpec Blackbox Testing & Live Example Generation

Verify that an existing ARM control-plane **TypeSpec** specification (`tspconfig.yaml` + `main.tsp` under `specification/<service>/resource-manager/**`) matches **actual deployed Azure service wire behavior** for a target `api-version`, drive stateful resource lifecycle execution toward **100% operation coverage**, and synthesize sanitized real-life TypeSpec example JSON files (`examples/<api-version>/*.json`).

## Core Design Principles

1. **Purely TypeSpec-Native (Zero Swagger / Zero OAV)**: Compiles `main.tsp` directly in-memory via `@typespec/compiler` (`noEmit: true`), projects to the target `api-version` via `@typespec/versioning`, extracts HTTP/LRO/paging/visibility/`@secret` contracts and `.tsp:line` provenance directly from the TypeSpec `Program`, and validates live wire payloads and generated examples directly against TypeSpec `Model`/`Union`/`Enum`/`Scalar` types. Never reads, emits, or mutates Swagger/OpenAPI JSON files.
2. **Auth via Azure CLI, Probes via Raw HTTP**: Use `az account get-access-token` strictly to obtain the ARM Bearer token. Never use `az <service>` commands to test API behavior—they wrap Python SDKs with baked-in API versions and client-side LRO polling that hide wire status codes and headers. Always execute probes through `.github/skills/azure-arm-blackbox-test/scripts/cli.ts`, which uses raw Node.js `fetch` (`redirect: "manual"`) with the exact `?api-version=<version>`.
3. **Provisioning Target Resources IS the Test**: Creating, reading, listing, updating, invoking actions on, deleting, and purging the target RP's resources are the stateful DAG steps that exercise the TypeSpec operations and capture real-life examples.
4. **Disposable Resource Group Isolation & Guaranteed Teardown**: Every mutating call is confined by a hard-coded guardrail (`assertSafeArmTarget`) to a dedicated `rg-arm-blackbox-<service>-<id>` Resource Group. External cross-RP dependencies (Managed Identity, VNet/Subnet, Private Endpoint, Storage Account, Log Analytics) are provisioned inside the same disposable RG as setup fixtures. Always execute `rg delete` in your completion/cleanup phase, even if individual probes fail.
5. **Read-Only Spec Boundary**: Never modify `.tsp` source files. Keep scratch traces, ledgers, reports, and candidate examples inside `--work-dir` by default; only write generated examples into `<typespec-project>/examples/<api-version>/` (`--write-to-spec`) when explicitly requested by the user.

## End-to-End Workflow

All CLI commands run from the repository root using Node 24's native TypeScript execution:

```bash
node .github/skills/azure-arm-blackbox-test/scripts/cli.ts <subcommand> [options]
```

### Step 1: Compile TypeSpec, Build Two-Layer DAG, and Choose Single vs. Sharded Execution

1. **Resolve Subscription & Run `discover` First**:
   Resolve the active Azure subscription (`az account show --query "{id:id, name:name}" -o json`), pick an isolated scratch `--work-dir` (for example under session artifacts or `$TEMP/arm-blackbox-<service>`), and compile the TypeSpec inventory & topological DAG:

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts discover \
     --spec specification/<service>/resource-manager \
     --api-version <target-api-version> \
     --subscription-id <subscription-id> \
     --location <location> \
     --check-live-provider \
     --work-dir <work-dir>
   ```

   _(Optional Canary / EUAP / Dogfood / Sovereign cloud target: pass `--arm-base-url <https-url>`, `--arm-token-resource <audience>`, or `--allowed-arm-origins <csv>`. Optional `--resource-filter <csv>` narrows discovery while automatically retaining transitive intra-RP `create`/`delete` prerequisites ONLY when the user explicitly asked for a subset.)_

   Inspect the JSON output and `<work-dir>/coverage-ledger.json`:
   - Confirm `providerLiveMetadata.targetVersionSupportedOnArm` is `true`.
   - Review `executionOrder` and `executionGraph` (`{ nodes, edges }` capturing parent-before-child, intra-RP `SubResource` prerequisite edges, and reverse bottom-up delete order) plus `externalDependencies` (self-RP leaf noise is pre-filtered; cross-RP host scopes and root external fixtures are listed).

2. **Scale Branch — Single-RG (`<= 60` ops) vs. Sharded Parallel Execution (`> 60` ops)**:
   - **Small/Medium Specs (`totalOperations <= 60`)**: Create one disposable Resource Group directly in `<work-dir>`:
     ```bash
     node .github/skills/azure-arm-blackbox-test/scripts/cli.ts rg create \
       --work-dir <work-dir> \
       --subscription-id <subscription-id> \
       --location <location> \
       --service-hint <service>
     ```
   - **Large/Monolithic Specs (`totalOperations > 60`, e.g. `Microsoft.Network` with `800+` operations)**: Never attempt 800+ sequential cold probes in a single agent turn. Partition `<work-dir>` into balanced, self-contained shards (`--max-ops-per-shard 140` by default; prerequisite `create`/`delete` contracts are automatically included in each shard):
     ```bash
     node .github/skills/azure-arm-blackbox-test/scripts/cli.ts partition-shards \
       --work-dir <work-dir>
     ```
     Delegate shards in parallel across subagents (each shard worker runs `rg create --work-dir <shard-dir>`, executes Step 2b–Step 3 using `probe-batch` until `cli.ts status --work-dir <shard-dir>` shows `pending === 0`, runs `generate-examples --work-dir <shard-dir>`, and runs `rg delete --work-dir <shard-dir> --wait`). Once all shards complete, merge them back into `<work-dir>`:
     ```bash
     node .github/skills/azure-arm-blackbox-test/scripts/cli.ts merge-shards \
       --work-dir <work-dir>
     ```

3. **DAG Layer 2 — Weave External Cross-RP Fixtures (`fixture`)**:
   When operations require cross-RP dependencies (`managed-identity`, `vnet-subnet`, `private-endpoint`, `storage-account`, `log-analytics`, or any arbitrary cross-RP resource via `--kind custom`), provision them inside the disposable RG via `fixture` (never via raw `az rest` or `az <service>`):

   ```bash
   # Built-in cross-RP fixture:
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts fixture \
     --work-dir <work-dir> \
     --kind managed-identity

   # Arbitrary cross-RP fixture inside the disposable RG (e.g. Key Vault, Compute VM, EventHub):
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts fixture \
     --work-dir <work-dir> \
     --kind custom \
     --resource-path "providers/Microsoft.KeyVault/vaults/bbxkv01" \
     --api-version 2023-07-01 \
     --body-file <work-dir>/requests/kv-fixture.json
   ```

   _(Provision `private-endpoint` fixtures mid-loop after the parent target RP resource is created so you can pass `--target-resource-id <resourceId> --group-ids <groupId>`.)_

### Step 2: Execute Stateful Lifecycle Probes Until `pending === 0`

Drive every operation in `executionOrder` using **warm batch execution (`probe-batch`)** for throughput and `probe` for targeted interactive retries:

```bash
# Warm batch execution: compiles TypeSpec ONCE in-memory for 10-50+ operations!
node .github/skills/azure-arm-blackbox-test/scripts/cli.ts probe-batch \
  --work-dir <work-dir> \
  --batch-file <work-dir>/requests/batch-01.json

# Fast zero-body batch for preflight/GET/LIST operations:
node .github/skills/azure-arm-blackbox-test/scripts/cli.ts probe-batch \
  --work-dir <work-dir> \
  --operations Operations_List,Usages_List,VirtualNetworks_ListAll

# Inspect live coverage counts and next ready pending operations at any time:
node .github/skills/azure-arm-blackbox-test/scripts/cli.ts status \
  --work-dir <work-dir>
```

Follow the [lifecycle playbook](references/fixture-and-lifecycle-playbook.md):

1. **Preflight discovery ops**: Run provider/subscription/location discovery operations (`Operations_List`, `CheckNameAvailability`, `CheckDnsNameAvailability`, SKU/usage/service-tag lists — passing `--query '<json>'` or `query` in batch JSON when required query parameters exist).
2. **Negative error-envelope probe**: Before creating a parent resource, send one `GET` for the non-existent resource with `"expectError": true` and `"scenario": "not-found"` to validate the `404` OData v4 `{ error: { code, message } }` contract (`ERROR-ENVELOPE-DRIFT`). (`expectError: true` also polls `202` LROs when an invalid action fails asynchronously.)
3. **Prerequisite & Parent Resource Lifecycle (`executionGraph` topological order)**:
   - Follow `intraRpDependencies` and `executionGraph`: create prerequisite intra-RP resources first (for example `VirtualNetworks` + `Subnets` + `PublicIPAddresses` + `NetworkSecurityGroups` before `NetworkInterfaces`, `LoadBalancers`, `NatGateways`, `BastionHosts`, or `AzureFirewalls`). Do **not** skip long-running resources—LRO polling is uncapped by default with automatic ARM token refresh.
   - `PUT`: Omit `pathOrUrl` to let `probe` deterministically interpolate `contract.pathTemplate` from ledger context and poll LRO headers (`Azure-AsyncOperation`, `Location`, `Operation-Location`) to terminal completion.
   - `GET`, `LIST` (RG + Subscription), `PATCH`, `POST` actions: Batch ready `GET`/`LIST`/`PATCH`/`POST` operations in `probe-batch` after parent creation succeeds.
4. **Child & Extension Resources**: Provision any dependent fixtures (`private-endpoint` or `--kind custom`), then execute child `PUT` -> `GET` -> `LIST` -> `PATCH` -> `POST` -> `DELETE`.
5. **Bottom-Up `DELETE` & Soft-Deleted Operations**: Delete dependent/child resources before prerequisite/parent resources (`executionOrder` automatically reverses topological tiers on `DELETE`), then immediately exercise `deleted*` operations (`ListDeleted`, `GetDeleted`, `PurgeDeleted`).
6. **Adaptive `4xx` Retry Loop & Hard `pending === 0` Completion Gate**:
   - **Hard Gate**: You MUST reach `pending === 0` in `cli.ts status --work-dir <work-dir>` before tearing down the RG or concluding. Never leave operations `pending` due to time estimates or context budgeting.
   - If a probe returns `400`/`409`/`422` due to missing domain fields, SKU/location combos, or naming rules, read the exact ARM error message, adjust the request payload, and re-probe. (`SCHEMA-REQUEST-REJECTED` is recorded automatically when `requestSchemaErrorCount === 0`.)
   - Use `mark-blocked` **only** after live evidence proves an external blocker:
     1. A live `4xx` response proving subscription quota exhaustion (`*LimitReached`, `QuotaExceeded`), unregistered feature/allowlist (`FeatureNotRegistered`, `SubscriptionNotRegisteredForFeature`), physical/carrier/BYOIP/cross-tenant ownership requirement, or unsupported region/SKU across fallback regions; OR
     2. A non-RG scope guardrail (`Tenant`, `ManagementGroup`, cross-subscription, or cross-RP host resource that cannot be created inside the disposable RG).
   - When a parent resource's `CreateOrUpdate` is live-verified as externally blocked after retry, mark its dependent child operations blocked in one atomic call citing the exact live ARM error code:
     ```bash
     node .github/skills/azure-arm-blackbox-test/scripts/cli.ts mark-blocked \
       --work-dir <work-dir> \
       --resource-type Microsoft.Network/expressRouteDirectPorts \
       --reason "Parent ExpressRouteDirectPorts_CreateOrUpdate blocked by live 400 InvalidPeeringLocation/physical port requirement"
     ```

### Step 3: Generate Sanitized Real-Life TypeSpec Examples

Run `generate-examples` to convert verified live traces into TypeSpec example JSON files and validate them directly against the projected TypeSpec `HttpOperation` models:

```bash
node .github/skills/azure-arm-blackbox-test/scripts/cli.ts generate-examples \
  --work-dir <work-dir>
```

- By default, `generate-examples` writes pure wire-truth examples (containing strictly the HTTP status codes, headers, and bodies observed on the live wire) to `<work-dir>/examples/<api-version>/*.json` without modifying the repository.
- Pass `--write-to-spec` **only** when the user asked to promote examples into `<typespec-project>/examples/<api-version>/*.json`. `--write-to-spec` writes **only** examples that are both TypeSpec-valid (`schemaValid: true`) and OAV-complete (`oavComplete: true` — covering all declared `2xx` status codes for `OAV111` and required `Location` / `Azure-AsyncOperation` headers on `202` LROs), and reports any skipped wire-subset operations.
- Consult [references/example-sanitization-and-wiring.md](references/example-sanitization-and-wiring.md) for secret redaction (`SEC-SECRET-DETECT`), PII scrubbing, pure wire-truth LRO stitching, and `--write-to-spec` OAV-completeness gating.

### Step 4: Tear Down Disposable RG(s) and Render Final Report

1. Confirm `cli.ts status --work-dir <work-dir>` shows `pending: 0`, then delete the disposable Resource Group (`rg delete` blocks teardown if any operation is still `pending`, unless `--allow-pending` is passed for emergency abort cleanup):

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts rg delete \
     --work-dir <work-dir> \
     --wait
   ```

   _(In sharded mode, each shard worker already ran `rg delete --work-dir <shard-dir> --wait` before `merge-shards`; verify `az group list --query "[?starts_with(name, 'rg-arm-blackbox-')]"` returns `[]`.)_

2. Generate `<work-dir>/blackbox-report.json`, `<work-dir>/blackbox-report.md`, and the self-contained local interactive HTML dashboard `<work-dir>/report-html/index.html` (with `assets/{styles.css,app.js,portal-data.js,portal-data.json}` — works offline via `file://` or any local HTTP server; pass repeatable `--extra-work-dir <dir>` to combine multiple service runs):

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts report \
     --work-dir <work-dir>
   ```

3. Consult [references/behavioral-discrepancy-rules.md](references/behavioral-discrepancy-rules.md) to summarize the API coverage percentage, parameter coverage, detected TypeSpec-vs-service behavioral discrepancies (with `.tsp:line` citations), generated real-life examples, and the path to `<work-dir>/report-html/index.html`. Do not modify `.tsp` files.
