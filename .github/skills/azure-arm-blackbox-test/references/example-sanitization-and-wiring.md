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

## 2. LRO Dual-Response Assembly (`EX-COVERAGE`)

Repository rule `EX-COVERAGE` requires LRO examples to include **both** the initial async response (`201` or `202`, including declared polling headers) and the terminal response (`200` or `204`):

- For `PUT` returning `201` (initial `Creating`) followed by `final-get` `200` (`Succeeded`), `generate-examples` populates both `"201"` and `"200"` in `responses`.
- For `PUT` returning `200` (`Creating`) followed by `final-get` `200` (`Succeeded`), `responses["200"]` records the terminal `Succeeded` payload.
- For async `DELETE` / void `POST` returning `202` and completing with no body, `generate-examples` populates `"202"` (with declared headers) plus `"200": {}` or `"204": {}` according to TypeSpec declared status codes.

## 3. Native TypeSpec Example Validation & Writing (`scripts/typespec-validator.ts`)

- By default, `generate-examples` writes candidate examples only to `<work-dir>/examples/<api-version>/` and validates them directly in-memory against the projected TypeSpec `HttpOperation` parameter and response models (`validateExampleAgainstTypeSpec`).
- Wire-contract discrepancies (`SCHEMA-RESPONSE-DRIFT`, `UNION_CASE_MISMATCH`, etc.) are evaluated exclusively on the unsanitized live HTTP exchanges in `execute-probe.ts`. Post-sanitization example validation in `generate-examples` ensures that redaction placeholders and assembled dual LRO responses remain valid against TypeSpec constraints (`@pattern`, `@minLength`, `@maxLength`).
- When `--write-to-spec` is explicitly requested, only schema-valid examples (`schemaValid: true`, or when `--skip-schema-check` is passed) are copied to `<typespecProjectDir>/examples/<api-version>/<ExampleName>.json` (never touching or generating Swagger files).
