# Stateful ARM Lifecycle & External Fixture Playbook

Achieving 100% operation coverage on an ARM service requires executing operations in dependency order so that parent state, child state, cross-RP links, and soft-deleted tombstones exist at the exact moment their dependent operations run.

## 1. Standard Topological Execution Sequence

`discover` (`scripts/plan-inventory.ts`) orders operations into these phases:

1. **`preflight-discovery`**:
   - `Operations_List` (`/providers/<Namespace>/operations`)
   - `CheckNameAvailability` (test both an available name and, after parent creation, an already-taken name!)
   - Location quota / SKU / usage list operations
2. **External Cross-RP Setup Fixtures** (`cli.ts fixture`):
   - Provisioned inside the same `rg-arm-blackbox-<svc>-<rand>` Resource Group before creating resources that reference them:
     - `--kind managed-identity`: Creates `Microsoft.ManagedIdentity/userAssignedIdentities` so `identity.type = "SystemAssigned, UserAssigned"` can be tested on the parent resource.
     - `--kind vnet-subnet`: Creates `Microsoft.Network/virtualNetworks` (`10.42.0.0/16`, `default` subnet with `privateEndpointNetworkPolicies: "Disabled"`).
     - `--kind storage-account`: Creates `Microsoft.Storage/storageAccounts` (`Standard_LRS`, `StorageV2`, `allowBlobPublicAccess: false`).
     - `--kind log-analytics`: Creates `Microsoft.OperationalInsights/workspaces` (`PerGB2018`).
     - `--kind custom --resource-path "providers/<RP>/<type>/<name>" --api-version <ver> --body-file <json>`: Safely provisions any other cross-RP prerequisite (Key Vault, Compute VM, EventHub, ServiceBus, etc.) inside the disposable RG with full RG-ownership and cross-scope Resource ID guardrails.
3. **Negative Pre-Create Check (`expectError: true`)**:
   - Call parent `GET` before `PUT` to elicit a safe `404 ResourceNotFound` and verify the RP's error envelope without risking mutation.
4. **Parent Resource Lifecycle (`depth = 1`)**:
   - `PUT` (Create): Use SKU tiers that support child operations (for example, `Standard` SKU on `Microsoft.AppConfiguration/configurationStores` enables `Replicas`, `Snapshots`, `PrivateEndpointConnections`, and soft-delete `DeletedConfigurationStores`, whereas `Free` blocks them!).
   - `GET`: Include `"priorPutBody"` in the probe request JSON to verify round-trip property persistence.
   - `LIST` (by Resource Group and by Subscription): Verify `value` collection and `nextLink` continuation.
   - `PATCH`: Update `tags` and at least one mutable `properties.*` field.
   - `POST` actions: Run non-destructive actions first (e.g., `listKeys`), then mutating actions (e.g., `regenerateKey`).
5. **Post-Parent External Fixtures (`private-endpoint`)**:
   - Once the parent resource exists and exposes its `id`, run:
     ```bash
     node .github/skills/azure-arm-blackbox-test/scripts/cli.ts fixture \
       --work-dir <work-dir> \
       --kind private-endpoint \
       --target-resource-id <parentResourceId> \
       --group-ids <groupIdFromPrivateLinkResourcesList>
     ```
   - Call `PrivateLinkResources_ListBy*` / `Get` first to discover exact `groupIds` dynamically!
   - Once the Private Endpoint exists, `PrivateEndpointConnections_List`, `Get`, `CreateOrUpdate` (e.g. updating `privateLinkServiceConnectionState.description` / `status`), and `Delete` can all be exercised against a real Azure Private Endpoint connection!
6. **Child & Extension Resources (`depth >= 2`)**:
   - Execute `PUT` -> `GET` -> `LIST` -> `PATCH` -> `POST` -> `DELETE` for each child type (`KeyValues`, `Replicas`, `Snapshots`, etc.).
   - Note special child naming rules from parameter patterns (for example, `KeyValues` uses `key$label` URL-encoded as `myKey%24myLabel`; `NetworkSecurityPerimeterConfigurations` requires an NSP association and may offer `reconcile`).
7. **Bottom-Up Deletion & Soft-Deleted Resource Lifecycle**:
   - Delete remaining child resources first (`Replicas_Delete`, `PrivateEndpointConnections_Delete`, etc.—note some immutable snapshots have no DELETE and expire via retention).
   - Delete the parent resource (`DELETE`), polling LRO to completion.
   - Immediately test `deleted*` operations (`DeletedConfigurationStores_List`, `GetDeleted`, `PurgeDeleted`) using the location and name of the just-deleted store!
8. **Disposable Resource Group Teardown**:
   - Always finish with `cli.ts rg delete --work-dir <work-dir>`.

## 2. Probe Request JSON Format

Pass `--request-file <file.json>` to `cli.ts probe`. `pathOrUrl` is optional—when omitted, `probe` deterministically interpolates `contract.pathTemplate` from `coverage-ledger.json` (`{subscriptionId}`, `{resourceGroupName}`, `{location}`, saved resource names, and `*_List*` child item names) and auto-attaches saved `priorPutBody` on `GET` probes. Supply `pathParams` only for ~10% semantic overrides (`key$label`, `/{scope}`, or secondary regions):

```json
{
  "operationId": "ConfigurationStores_Create",
  "scenario": "StandardStore",
  "body": {
    "location": "eastus",
    "sku": { "name": "Standard" },
    "tags": { "env": "blackbox" },
    "properties": {
      "softDeleteRetentionInDays": 1
    }
  },
  "pollLro": true
}
```

- **Use Exact TypeSpec Union/Enum Variant Casing**: Always populate request enum/union fields with the exact literal casing declared in the TypeSpec `union`/`enum` definition (for example `"Key"` from `union CompositionType`, never lowercase `'key'` from prose `@doc` comments), because ARM RPs often echo the caller's raw input casing in the initial `201` response before normalizing in the async worker.
