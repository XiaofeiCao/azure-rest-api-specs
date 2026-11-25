#!/usr/bin/env node

import * as fs from "node:fs";
import { parseArgs } from "node:util";
import { executeOperationProbe } from "./execute-probe.ts";
import { generateLiveExamples } from "./generate-examples.ts";
import { loadLedger, saveLedger } from "./ledger-store.ts";
import {
  createDisposableResourceGroup,
  deleteDisposableResourceGroup,
  provisionExternalFixture,
} from "./manage-rg.ts";
import { discoverSpecInventory } from "./plan-inventory.ts";
import { buildSummaryReport } from "./render-report.ts";
import type { ExternalDependencyKind, ProbeRequestInput } from "./types.ts";

export async function runCli(argv: string[]): Promise<void> {
  const [subcommand, ...rest] = argv;

  if (!subcommand || subcommand === "--help" || subcommand === "-h") {
    console.log(
      [
        "Usage: node scripts/cli.ts <command> [options]",
        "",
        "Commands:",
        "  rg                 Create or delete the disposable test Resource Group (create | delete)",
        "  discover           Compile ARM TypeSpec in-memory for an api-version and build the base DAG in coverage-ledger.json",
        "  fixture            Provision an external cross-RP setup fixture inside the disposable RG",
        "  probe              Execute a raw HTTP operation probe with wire-level LRO polling & TypeSpec validation",
        "  mark-blocked       Record an explicit Azure quota/feature/environment blocker for an operation",
        "  generate-examples  Generate sanitized real-life TypeSpec example JSON files and validate against TypeSpec",
        "  report             Render blackbox-report.json, blackbox-report.md, and interactive local report-html/index.html",
      ].join("\n"),
    );
    return;
  }

  if (subcommand === "discover") {
    const { values } = parseArgs({
      args: rest,
      options: {
        spec: { type: "string" },
        "api-version": { type: "string" },
        "work-dir": { type: "string" },
        "subscription-id": { type: "string" },
        location: { type: "string" },
        "arm-base-url": { type: "string" },
        "arm-token-resource": { type: "string" },
        "allowed-arm-origins": { type: "string" },
        "check-live-provider": { type: "boolean", default: false },
        reset: { type: "boolean", default: false },
      },
    });
    if (!values.spec || !values["work-dir"]) {
      throw new Error("discover requires --spec <path> and --work-dir <dir>");
    }
    const ledger = await discoverSpecInventory({
      specPath: values.spec,
      apiVersion: values["api-version"],
      workDir: values["work-dir"],
      subscriptionId: values["subscription-id"],
      location: values.location,
      armBaseUrl: values["arm-base-url"],
      armTokenResource: values["arm-token-resource"],
      allowedArmOrigins: values["allowed-arm-origins"]
        ? values["allowed-arm-origins"]
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
        : undefined,
      checkLiveProvider: values["check-live-provider"],
      reset: values.reset,
    });
    console.log(
      JSON.stringify(
        {
          providerNamespace: ledger.providerNamespace,
          apiVersion: ledger.apiVersion,
          availableApiVersions: ledger.availableApiVersions,
          typespecProjectDir: ledger.typespecProjectDir,
          entrypointFile: ledger.entrypointFile,
          totalOperations: ledger.executionOrder.length,
          executionOrder: ledger.executionOrder,
          externalDependencies: ledger.externalDependencies,
          providerLiveMetadata: ledger.providerLiveMetadata
            ? {
                registrationState: ledger.providerLiveMetadata.registrationState,
                targetVersionSupportedOnArm:
                  ledger.providerLiveMetadata.targetVersionSupportedOnArm,
                recommendedLocations: ledger.providerLiveMetadata.recommendedLocations,
              }
            : undefined,
        },
        null,
        2,
      ),
    );
    return;
  }

  if (subcommand === "rg") {
    const [action, ...rgArgs] = rest;
    const { values } = parseArgs({
      args: rgArgs,
      options: {
        "work-dir": { type: "string" },
        "subscription-id": { type: "string" },
        location: { type: "string" },
        name: { type: "string" },
        "service-hint": { type: "string" },
        "arm-base-url": { type: "string" },
        "arm-token-resource": { type: "string" },
        "allowed-arm-origins": { type: "string" },
        wait: { type: "boolean", default: false },
      },
    });
    if (!values["work-dir"]) {
      throw new Error("rg requires --work-dir <dir>");
    }
    if (action === "create") {
      const created = await createDisposableResourceGroup({
        workDir: values["work-dir"],
        subscriptionId: values["subscription-id"],
        location: values.location,
        rgName: values.name,
        serviceHint: values["service-hint"],
        armBaseUrl: values["arm-base-url"],
        armTokenResource: values["arm-token-resource"],
        allowedArmOrigins: values["allowed-arm-origins"]
          ? values["allowed-arm-origins"]
              .split(",")
              .map((s) => s.trim())
              .filter(Boolean)
          : undefined,
      });
      console.log(JSON.stringify(created, null, 2));
      return;
    }
    if (action === "delete") {
      const deleted = await deleteDisposableResourceGroup({
        workDir: values["work-dir"],
        wait: values.wait,
      });
      console.log(JSON.stringify(deleted, null, 2));
      return;
    }
    throw new Error(`Unknown rg action "${action ?? ""}". Expected "create" or "delete".`);
  }

  if (subcommand === "fixture") {
    const { values } = parseArgs({
      args: rest,
      options: {
        "work-dir": { type: "string" },
        kind: { type: "string" },
        name: { type: "string" },
        "target-resource-id": { type: "string" },
        "group-ids": { type: "string" },
      },
    });
    if (!values["work-dir"] || !values.kind) {
      throw new Error("fixture requires --work-dir <dir> and --kind <kind>");
    }
    const fixture = await provisionExternalFixture({
      workDir: values["work-dir"],
      kind: values.kind as ExternalDependencyKind,
      name: values.name,
      targetPrivateLinkResourceId: values["target-resource-id"],
      groupIds: values["group-ids"]
        ? values["group-ids"]
            .split(",")
            .map((s) => s.trim())
            .filter(Boolean)
        : undefined,
    });
    console.log(JSON.stringify(fixture, null, 2));
    return;
  }

  if (subcommand === "probe") {
    const { values } = parseArgs({
      args: rest,
      options: {
        "work-dir": { type: "string" },
        "request-file": { type: "string" },
        "operation-id": { type: "string" },
        path: { type: "string" },
        "path-params": { type: "string" },
        scenario: { type: "string" },
        body: { type: "string" },
        "expect-error": { type: "boolean", default: false },
        "no-poll": { type: "boolean", default: false },
      },
    });
    if (!values["work-dir"]) {
      throw new Error("probe requires --work-dir <dir>");
    }

    let probeInput: ProbeRequestInput;
    if (values["request-file"]) {
      probeInput = JSON.parse(fs.readFileSync(values["request-file"], "utf8")) as ProbeRequestInput;
    } else {
      if (!values["operation-id"]) {
        throw new Error(
          "probe requires either --request-file <json> or --operation-id <id> (with optional --path <armPath> or --path-params <json>)",
        );
      }
      probeInput = {
        operationId: values["operation-id"],
        ...(values.path ? { pathOrUrl: values.path } : {}),
        ...(values["path-params"]
          ? { pathParams: JSON.parse(values["path-params"]) as Record<string, string> }
          : {}),
        scenario: values.scenario,
        expectError: values["expect-error"],
        pollLro: !values["no-poll"],
        body: values.body ? (JSON.parse(values.body) as unknown) : undefined,
      };
    }

    const { trace, traceFile } = await executeOperationProbe({
      workDir: values["work-dir"],
      input: probeInput,
    });
    console.log(
      JSON.stringify(
        {
          operationId: trace.operationId,
          scenario: trace.scenario,
          probeSucceeded: trace.probeSucceeded,
          failureReason: trace.failureReason,
          sourceLocation: trace.sourceLocation,
          initialStatus: trace.exchanges[0]?.response.status,
          exchangeCount: trace.exchanges.length,
          observedLro: trace.observedLro,
          requestSchemaErrorCount: trace.requestSchemaErrors.length,
          responseSchemaErrorCount: trace.responseSchemaErrors.length,
          discrepancies: trace.discrepancies,
          traceFile,
        },
        null,
        2,
      ),
    );
    return;
  }

  if (subcommand === "mark-blocked") {
    const { values } = parseArgs({
      args: rest,
      options: {
        "work-dir": { type: "string" },
        "operation-id": { type: "string" },
        reason: { type: "string" },
      },
    });
    if (!values["work-dir"] || !values["operation-id"] || !values.reason) {
      throw new Error("mark-blocked requires --work-dir <dir> --operation-id <id> --reason <text>");
    }
    const ledger = loadLedger(values["work-dir"]);
    const cov = ledger.coverage[values["operation-id"]];
    if (!cov) {
      throw new Error(`Unknown operationId "${values["operation-id"]}"`);
    }
    cov.status = "blocked";
    cov.blockerReason = values.reason;
    saveLedger(values["work-dir"], ledger);
    console.log(JSON.stringify(cov, null, 2));
    return;
  }

  if (subcommand === "generate-examples") {
    const { values } = parseArgs({
      args: rest,
      options: {
        "work-dir": { type: "string" },
        "write-to-spec": { type: "boolean", default: false },
        "skip-schema-check": { type: "boolean", default: false },
      },
    });
    if (!values["work-dir"]) {
      throw new Error("generate-examples requires --work-dir <dir>");
    }
    const generated = await generateLiveExamples({
      workDir: values["work-dir"],
      writeToSpec: values["write-to-spec"],
      validateWithTypeSpec: !values["skip-schema-check"],
    });
    if (values["write-to-spec"]) {
      const promotedCount = generated.filter((g) => g.writtenSpecPaths.length > 0).length;
      const skipped = generated.filter((g) => g.specWriteSkippedReason);
      console.error(
        `[generate-examples] --write-to-spec promoted ${promotedCount}/${generated.length} example(s) to spec; skipped ${skipped.length} incomplete/invalid example(s).`,
      );
      for (const item of skipped) {
        console.error(
          `  - ${item.exampleName} (${item.operationId}): ${item.specWriteSkippedReason}`,
        );
      }
    }
    console.log(JSON.stringify(generated, null, 2));
    return;
  }

  if (subcommand === "report") {
    const { values } = parseArgs({
      args: rest,
      options: {
        "work-dir": { type: "string" },
        "extra-work-dir": { type: "string", multiple: true },
        "html-dir": { type: "string" },
        "no-html": { type: "boolean", default: false },
      },
    });
    if (!values["work-dir"]) {
      throw new Error("report requires --work-dir <dir>");
    }
    const { jsonPath, markdownPath, htmlDir, htmlIndexPath, report } = await buildSummaryReport(
      values["work-dir"],
      {
        emitHtml: !values["no-html"],
        extraWorkDirs: values["extra-work-dir"],
        htmlOutputDir: values["html-dir"],
      },
    );
    console.log(
      JSON.stringify(
        {
          jsonPath,
          markdownPath,
          ...(htmlDir ? { htmlDir } : {}),
          ...(htmlIndexPath ? { htmlIndexPath } : {}),
          coverageSummary: report.coverageSummary,
          discrepancySummary: report.discrepancySummary,
          generatedExamplesCount: report.generatedExampleFiles.length,
        },
        null,
        2,
      ),
    );
    return;
  }

  throw new Error(`Unknown command "${subcommand}". Run with --help for usage.`);
}

if (import.meta.main) {
  runCli(process.argv.slice(2)).catch((err: unknown) => {
    console.error(err instanceof Error ? err.message : String(err));
    process.exitCode = 1;
  });
}
