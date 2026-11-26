# TypeSpec Example Sanitization, LRO Dual Responses, and Validation Rules

Real-life TypeSpec examples (`examples/<api-version>/*.json`) captured from live Azure services must never leak live credentials or personal subscription metadata and must comply with repository example rules (`EX-PAYLOAD`, `EX-COVERAGE`, `EX-ORPHAN`, `SEC-SECRET-DETECT`).

## 1. Automatic Sanitization (`scripts/sanitize-example.ts`)

`generate-examples` automatically applies the following transformations before writing any example file:

- **Subscription, Identity GUIDs & PII**:
  - Subscription ID (in parameters, URLs, and nested ARM resource IDs) -> `00000000-0000-0000-0000-000000000000`
  - `tenantId` -> `11111111-1111-1111-1111-111111111111`
  - `principalId` -> `22222222-2222-2222-2222-222222222222`
  - `clientId` -> `33333333-3333-3333-3333-333333333333`
  - `createdBy` / `lastModifiedBy` email addresses -> `user@contoso.com`
- **Resource Group Normalization**:
  - `rg-arm-blackbox-*` -> `contosoResourceGroup`
- **Secret & Credential Scrubbing (`SEC-SECRET-DETECT`)**:
  - Properties decorated with `@secret` in TypeSpec or matching secret key heuristics (`password`, `secret`, `connectionString`, `primaryKey`, `secondaryKey`, `accessKey`, `apiKey`, `sasToken`, `sharedKey`, `token`, plus `ApiKey.value` fields adjacent to `connectionString`) are replaced with `<redacted>` (or `Endpoint=https://contoso.azconfig.io;Id=0000;Secret=<redacted>` for connection strings).
  - Embedded `AccountKey=...`, `SharedAccessKey=...`, `Secret=...`, SAS/ARM URL signing params (`sig=`, `c=`, `s=`, `h=`), and JWT (`eyJ...`) substrings inside arbitrary strings are redacted automatically.
  - HTTP `Authorization`, `Cookie`, and `Set-Cookie` headers are stripped at capture time before traces are written to disk.

Always spot-check generated example JSON files for service-specific custom secret field names before committing to `specification/`.

## 2. Pure Wire-Truth Response Assembly (`scripts/generate-examples.ts`)

`generate-examples` enforces **strict wire-truth** across every generated example — it never synthesizes, backfills, or clones un-observed `2xx` status codes, headers, or bodies:

- **Initial exchange**: Always records the actual HTTP status code (`initial.response.status`), declared response headers present on the wire (plus sanitized wire-observed `Azure-AsyncOperation`, `Location`, `Operation-Location`, and `Retry-After` headers on `201`/`202` LRO responses), and the sanitized response body if present.
- **Completed LRO terminal exchange**: Adds a second response entry **only** when an LRO was genuinely detected and completed cleanly on the wire, and a real terminal operation response was observed (`final-get` `2xx`, a terminal non-`202` `Location` / `resource-get` poll response, or an unwrapped `result`/`properties` payload from a `POST` status monitor).
  - For example, `PUT` returning `201` (`Creating`) followed by `final-get` `200` (`Succeeded`) populates both `"201"` and `"200"` from real wire exchanges.
  - Synchronous completions of multi-status or LRO-declared operations (such as a `DELETE` declaring `200 | 202 | 204` that returns synchronous `HTTP 204` on the wire) emit **only** `"204": {}` — never a fabricated headerless `"202": {}` or `"200": {}`.
  - Async `DELETE` operations monitored via `Azure-AsyncOperation` (where the status monitor returns an `OperationStatusResult` envelope rather than a `DELETE` response) emit **only** `"202"` with its sanitized LRO polling headers.

## 3. Native TypeSpec Validation & `--write-to-spec` OAV-Completeness Gating

- **Scratch output (`<work-dir>/examples/<api-version>/`)**: Always receives pure wire-truth example JSON files for all positive `2xx` traces (including wire-subset runs) and surfaces them in `<work-dir>/report-html/index.html` with `OAV-Complete` vs. `Wire-Subset` badges.
- **In-memory TypeSpec validation (`scripts/typespec-validator.ts`)**: Validates generated examples directly against projected TypeSpec `HttpOperation` parameter and response models (`validateExampleAgainstTypeSpec`) to confirm redaction placeholders satisfy `@pattern`, `@minLength`, and `@maxLength` constraints. Wire-contract discrepancies (`SCHEMA-RESPONSE-DRIFT`, `UNION_CASE_MISMATCH`, etc.) remain evaluated exclusively on unsanitized live HTTP exchanges in `execute-probe.ts`.
- **`--write-to-spec` OAV-completeness gate (`evaluateExampleOavCompleteness`)**: Because `azure-rest-api-specs` Swagger/OAV CI (`oav-runner`) enforces `OAV111` (`RESPONSE_STATUS_CODE_NOT_IN_EXAMPLE` — requiring every declared `2xx` code in `responses`) and `LRO_RESPONSE_HEADER` (requiring non-empty `Location` or `Azure-AsyncOperation` on `202` LRO responses for `POST`/`PATCH`/`DELETE`), `--write-to-spec` promotes **only** examples where `schemaValid && oavComplete` into `<typespecProjectDir>/examples/<api-version>/<ExampleName>.json`, and explicitly reports every skipped wire-subset operation with its observed vs. missing declared `2xx` status codes.
