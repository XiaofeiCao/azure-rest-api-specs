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

### Step 1: Discover Inventory, Check Live ARM Provider, and Build Lifecycle DAG

1. Resolve the active Azure subscription (`az account show --query "{id:id, name:name}" -o json`) and pick an isolated scratch `--work-dir` (for example under session artifacts or `$TEMP/arm-blackbox-<service>`).
2. Run `discover` with `--check-live-provider`:

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts discover \
     --spec specification/<service>/resource-manager \
     --api-version <target-api-version> \
     --subscription-id <subscription-id> \
     --check-live-provider \
     --work-dir <work-dir>
   ```

3. Inspect the JSON output and `<work-dir>/coverage-ledger.json`:
   - Confirm `providerLiveMetadata.targetVersionSupportedOnArm` is `true`. If `false`, inspect `providerLiveMetadata` in `coverage-ledger.json` to see which `apiVersions` are actually deployed on ARM and select or confirm a deployed `api-version` before running live probes.
   - Choose a region from `recommendedLocations` (defaulting to `eastus` / `eastus2` / `westus2`).
   - Review `executionOrder` and `externalDependencies`.

### Step 2: Create Disposable Test Resource Group & External Setup Fixtures

1. Create the disposable test RG:

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts rg create \
     --work-dir <work-dir> \
     --location <location>
   ```

2. When operations in `executionOrder` require cross-RP dependencies (`managed-identity`, `vnet-subnet`, `private-endpoint`, `storage-account`, `log-analytics`), provision them inside the disposable RG via `fixture` (see [references/fixture-and-lifecycle-playbook.md](references/fixture-and-lifecycle-playbook.md)):

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts fixture \
     --work-dir <work-dir> \
     --kind managed-identity
   ```

   _(Note: Provision `private-endpoint` fixtures after the parent target RP resource is created so you can pass `--target-resource-id <storeId> --group-ids <groupId>`.)_

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
   - `PUT` (`scenario: "create"` or `"min"` / `"max"`): Let `probe` automatically detect and poll LRO headers (`Azure-AsyncOperation`, `Location`, `Operation-Location`) or headerless non-terminal `provisioningState` transitions!
   - `GET`: Pass `"priorPutBody"` in the request JSON file so the analyzer checks `ROUNDTRIP-MUTABILITY-DRIFT` in addition to `PUT` terminal state.
   - `LIST` (by Resource Group and by Subscription): Automatically follows `nextLink` when present and checks `PAGEABLE-CONTRACT-DRIFT`.
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

- Pass `--write-to-spec` **only** when the user asked to write/update `<typespec-project>/examples/<api-version>/*.json`.
- Consult [references/example-sanitization-and-wiring.md](references/example-sanitization-and-wiring.md) for secret redaction (`SEC-SECRET-DETECT`), PII scrubbing, and LRO dual-response requirements (`EX-COVERAGE`).

### Step 5: Tear Down Disposable RG and Render Final Report

1. Always delete the disposable Resource Group before concluding:

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts rg delete \
     --work-dir <work-dir>
   ```

   _(Add `--wait` when synchronous confirmation of full RG deletion is desired.)_

2. Generate `<work-dir>/blackbox-report.json` and `<work-dir>/blackbox-report.md`:

   ```bash
   node .github/skills/azure-arm-blackbox-test/scripts/cli.ts report \
     --work-dir <work-dir>
   ```

3. Consult [references/behavioral-discrepancy-rules.md](references/behavioral-discrepancy-rules.md) to summarize the API coverage percentage, detected TypeSpec-vs-service behavioral discrepancies (with `.tsp:line` citations), and generated real-life examples. Do not modify `.tsp` files.
