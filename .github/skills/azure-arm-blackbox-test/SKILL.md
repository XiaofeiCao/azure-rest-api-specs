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

### Step 1: Isolate Disposable Test Resource Group

1. Resolve the active Azure subscription (`az account show --query "{id:id, name:name}" -o json`), pick an isolated scratch `--work-dir` (for example under session artifacts or `$TEMP/arm-blackbox-<service>`), and create the disposable `rg-arm-blackbox-*` Resource Group upfront:

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts rg create \
     --work-dir <work-dir> \
     --subscription-id <subscription-id> \
     --location <location> \
     --service-hint <service>
   ```

   _(Optional Canary / EUAP / Dogfood / Sovereign cloud target: pass `--arm-base-url <https-url>` such as `https://eastus2euap.management.azure.com` or `https://api-dogfood.resources.windows-int.net`, plus optional `--arm-token-resource <audience>` or `--allowed-arm-origins <csv>` when custom Entra audiences or companion LRO polling hosts are needed. Running `discover` before `rg create` is also supported.)_

### Step 2: Build Two-Layer Execution DAG (TypeSpec Base DAG + Cross-RP Fixture Weaving)

1. **DAG Layer 1 — Compile TypeSpec & Build Base Intra-Service DAG (`discover`)**:

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts discover \
     --spec specification/<service>/resource-manager \
     --api-version <target-api-version> \
     --check-live-provider \
     --work-dir <work-dir>
   ```

   Inspect the JSON output and `<work-dir>/coverage-ledger.json`:
   - Confirm `providerLiveMetadata.targetVersionSupportedOnArm` is `true` (if `false`, check deployed `apiVersions` in `providerLiveMetadata`).
   - Review `executionOrder` (top-down parent-to-child create/read/update/action, bottom-up delete, soft-delete purge) and `externalDependencies`.

2. **DAG Layer 2 — Weave External Cross-RP Fixtures (`fixture`)**:
   When operations in `executionOrder` require cross-RP dependencies (`managed-identity`, `vnet-subnet`, `private-endpoint`, `storage-account`, `log-analytics`), weave them into the lifecycle via `fixture` (see [references/fixture-and-lifecycle-playbook.md](references/fixture-and-lifecycle-playbook.md)):

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts fixture \
     --work-dir <work-dir> \
     --kind managed-identity
   ```

   _(Note: Provision `private-endpoint` fixtures mid-loop after the parent target RP resource is created so you can pass `--target-resource-id <storeId> --group-ids <groupId>`.)_

### Step 3: Execute Stateful Lifecycle Probes Toward 100% Coverage

Iterate through `executionOrder` in `coverage-ledger.json` using `probe`:

```bash
node .github/skills/azure-arm-blackbox-test/scripts/cli.ts probe \
  --work-dir <work-dir> \
  --request-file <work-dir>/requests/<op>.json
```

Follow the [lifecycle playbook](references/fixture-and-lifecycle-playbook.md):

1. **Preflight discovery ops**: Run `Operations_List`, `CheckNameAvailability`, SKU/quota list operations first.
2. **Negative error-envelope probe**: Before creating the parent resource, send one `GET` for the non-existent resource with `"expectError": true` and `"scenario": "not-found"` to validate the `404` OData v4 `{ error: { code, message } }` contract (`ERROR-ENVELOPE-DRIFT`).
3. **Parent resource lifecycle**:
   - `PUT` (`scenario: "create"` or `"min"` / `"max"`): Omit `pathOrUrl` to let `probe` deterministically interpolate `contract.pathTemplate` from ledger context (`{subscriptionId}`, `{resourceGroupName}`, `{location}`, and `@pattern`-valid resource names) and automatically poll LRO headers (`Azure-AsyncOperation`, `Location`, `Operation-Location`) or headerless non-terminal `provisioningState` transitions! Pass `pathParams` only when semantic overrides are needed (e.g., `key$label` or `/{scope}`).
   - `GET`: `probe` automatically reuses the created resource name and auto-attaches the saved `priorPutBody` from `PUT` so `ROUNDTRIP-MUTABILITY-DRIFT` is checked automatically without manual copy-paste.
   - `LIST` (by Resource Group and by Subscription): Automatically traverses all `nextLink` continuation pages, validates every page, and harvests child item names (such as server-assigned `privateEndpointConnectionName`) for subsequent child probes.
   - `PATCH`: Test mutable tags/properties update and LRO behavior.
   - `POST` actions (e.g., `listKeys`, `regenerateKey`, custom actions): Verifies sync vs LRO behavior and `final-state-via` payload delivery (`LRO-FINAL-STATE-DRIFT`).
4. **Child & extension resources**: Provision any dependent fixtures (such as a `private-endpoint` targeting the live parent resource so `PrivateEndpointConnections_List/Get/Put/Delete` can be exercised with real service state!), then run child `PUT` -> `GET` -> `LIST` -> `PATCH` -> `POST` -> `DELETE`.
5. **Parent `DELETE` & soft-deleted resource operations**: Delete child resources bottom-up, delete the parent resource, and then immediately exercise any `deleted*` operations (`ListDeleted`, `GetDeleted`, `PurgeDeleted`) while the soft-deleted entry exists!
6. **Adaptive 4xx Retry Loop**:
   - If a probe returns `400`/`409`/`422` because of a missing domain field, invalid SKU/location combo, or naming rule, read the exact ARM error message from the probe output, adjust the request JSON payload, and re-run `probe` to maximize coverage.
   - Note that if `requestSchemaErrorCount` was `0` on that `400`, `SCHEMA-REQUEST-REJECTED` is recorded automatically because the TypeSpec request model allowed a payload that the live service rejected!
   - Only use `mark-blocked` when an operation is genuinely gated by subscription quota, private feature flag (`FeatureNotRegistered`), or unsupported cloud stamp capability.

### Step 4: Generate Sanitized Real-Life TypeSpec Examples

Run `generate-examples` to convert verified live traces into TypeSpec example JSON files and validate them directly against the projected TypeSpec `HttpOperation` models:

```bash
node .github/skills/azure-arm-blackbox-test/scripts/cli.ts generate-examples \
  --work-dir <work-dir>
```

- By default, `generate-examples` writes pure wire-truth examples (containing strictly the HTTP status codes, headers, and bodies observed on the live wire) to `<work-dir>/examples/<api-version>/*.json` without modifying the repository.
- Pass `--write-to-spec` **only** when the user asked to promote examples into `<typespec-project>/examples/<api-version>/*.json`. `--write-to-spec` writes **only** examples that are both TypeSpec-valid (`schemaValid: true`) and OAV-complete (`oavComplete: true` — covering all declared `2xx` status codes for `OAV111` and required `Location` / `Azure-AsyncOperation` headers on `202` LROs), and reports any skipped wire-subset operations.
- Consult [references/example-sanitization-and-wiring.md](references/example-sanitization-and-wiring.md) for secret redaction (`SEC-SECRET-DETECT`), PII scrubbing, pure wire-truth LRO stitching, and `--write-to-spec` OAV-completeness gating.

### Step 5: Tear Down Disposable RG and Render Final Report

1. Always delete the disposable Resource Group before concluding:

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts rg delete \
     --work-dir <work-dir>
   ```

   _(Add `--wait` when synchronous confirmation of full RG deletion is desired.)_

2. Generate `<work-dir>/blackbox-report.json`, `<work-dir>/blackbox-report.md`, and the self-contained local interactive HTML dashboard `<work-dir>/report-html/index.html` (with `assets/{styles.css,app.js,portal-data.js,portal-data.json}` — works offline via `file://` or any local HTTP server; pass repeatable `--extra-work-dir <dir>` to combine multiple service runs):

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts report \
     --work-dir <work-dir>
   ```

3. Consult [references/behavioral-discrepancy-rules.md](references/behavioral-discrepancy-rules.md) to summarize the API coverage percentage, parameter coverage, detected TypeSpec-vs-service behavioral discrepancies (with `.tsp:line` citations), generated real-life examples, and the path to `<work-dir>/report-html/index.html`. Do not modify `.tsp` files.
