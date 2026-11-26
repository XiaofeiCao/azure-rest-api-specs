#!/usr/bin/env node

import { spawnSync } from "node:child_process";
import * as fs from "node:fs";
import { parseArgs } from "node:util";
import * as v8 from "node:v8";
import { executeOperationProbe, executeProbeBatch } from "./execute-probe.ts";
import { generateLiveExamples } from "./generate-examples.ts";
import { loadLedger, mergeShardWorkDirs, updateLedgerAtomically } from "./ledger-store.ts";
import {
  createDisposableResourceGroup,
  deleteDisposableResourceGroup,
  provisionExternalFixture,
} from "./manage-rg.ts";
import { discoverSpecInventory, partitionLedgerIntoShards } from "./plan-inventory.ts";
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
        "  discover           Compile ARM TypeSpec in-memory for an api-version and build the topological DAG in coverage-ledger.json",
        "  partition-shards   Partition a large discovered ledger into balanced self-contained shard work-dirs for parallel workers",
        "  merge-shards       Merge completed shard ledgers, traces, and examples back into the parent work-dir",
        "  status             Show coverage counts, pending operation breakdown by resource family/phase, and next ready DAG items",
        "  fixture            Provision an external cross-RP setup fixture (built-in or --kind custom) inside the disposable RG",
        "  probe              Execute a single raw HTTP operation probe with wire-level LRO polling & TypeSpec validation",
        "  probe-batch        Execute multiple probes/blocks in one warm in-memory TypeSpec process (zero recompilation overhead)",
        "  mark-blocked       Record a live-verified Azure quota/feature/scope blocker for one or more pending operations",
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
        "resource-filter": { type: "string", multiple: true },
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
      resourceFilter: values["resource-filter"],
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
          dagNodeCount: ledger.executionGraph?.nodes.length ?? 0,
          dagEdgeCount: ledger.executionGraph?.edges.length ?? 0,
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

  if (subcommand === "partition-shards") {
    const { values } = parseArgs({
      args: rest,
      options: {
        "work-dir": { type: "string" },
        "shard-count": { type: "string" },
        "max-ops-per-shard": { type: "string" },
        "output-dir": { type: "string" },
      },
    });
    if (!values["work-dir"]) {
      throw new Error("partition-shards requires --work-dir <dir>");
    }
    const manifest = partitionLedgerIntoShards({
      workDir: values["work-dir"],
      shardCount: values["shard-count"] ? Number(values["shard-count"]) : undefined,
      maxOpsPerShard: values["max-ops-per-shard"] ? Number(values["max-ops-per-shard"]) : undefined,
      outputDir: values["output-dir"],
    });
    console.log(JSON.stringify(manifest, null, 2));
    return;
  }

  if (subcommand === "merge-shards") {
    const { values } = parseArgs({
      args: rest,
      options: {
        "work-dir": { type: "string" },
        "shard-dir": { type: "string", multiple: true },
        "allow-active-shard-rgs": { type: "boolean", default: false },
      },
    });
    if (!values["work-dir"]) {
      throw new Error("merge-shards requires --work-dir <dir>");
    }
    const merged = mergeShardWorkDirs({
      parentWorkDir: values["work-dir"],
      shardDirs: values["shard-dir"],
      allowActiveShardRgs: values["allow-active-shard-rgs"],
    });
    console.log(JSON.stringify(merged, null, 2));
    return;
  }

  if (subcommand === "status") {
    const { values } = parseArgs({
      args: rest,
      options: {
        "work-dir": { type: "string" },
        phase: { type: "string" },
        "resource-type": { type: "string" },
        limit: { type: "string" },
      },
    });
    if (!values["work-dir"]) {
      throw new Error("status requires --work-dir <dir>");
    }
    const ledger = loadLedger(values["work-dir"]);
    const counts: Record<string, number> = {
      total: ledger.executionOrder.length,
      pending: 0,
      passed: 0,
      passed_with_mismatch: 0,
      failed_service_error: 0,
      blocked: 0,
      skipped: 0,
    };
    const pendingByFamily: Record<string, number> = {};
    const nextPending: Array<{
      operationId: string;
      method: string;
      phase: string;
      resourceType: string;
      pathTemplate: string;
      intraRpDependencies?: string[];
    }> = [];
    const maxItems = values.limit ? Math.max(1, Number(values.limit)) : 30;
    const phaseFilter = values.phase?.toLowerCase();
    const rtFilter = values["resource-type"]?.toLowerCase();

    for (const opId of ledger.executionOrder) {
      const cov = ledger.coverage[opId];
      const op = ledger.operations[opId];
      if (!cov || !op) continue;
      counts[cov.status] = (counts[cov.status] ?? 0) + 1;
      if (cov.status === "pending") {
        const segs = op.resourceType.split("/");
        const family = segs.length >= 2 ? `${segs[0]}/${segs[1]}` : op.resourceType;
        pendingByFamily[family] = (pendingByFamily[family] ?? 0) + 1;
        if (
          (!phaseFilter || op.phase.toLowerCase() === phaseFilter) &&
          (!rtFilter || op.resourceType.toLowerCase().includes(rtFilter)) &&
          nextPending.length < maxItems
        ) {
          nextPending.push({
            operationId: opId,
            method: op.method,
            phase: op.phase,
            resourceType: op.resourceType,
            pathTemplate: op.pathTemplate,
            ...(op.intraRpDependencies?.length
              ? { intraRpDependencies: op.intraRpDependencies }
              : {}),
          });
        }
      }
    }
    console.log(
      JSON.stringify(
        {
          serviceName: ledger.serviceName,
          apiVersion: ledger.apiVersion,
          disposableResourceGroup: ledger.disposableResourceGroup,
          counts,
          pendingByFamily,
          nextPending,
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
        "allow-pending": { type: "boolean", default: false },
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
      if (!values["allow-pending"]) {
        const ledger = loadLedger(values["work-dir"]);
        const pendingOps = Object.values(ledger.coverage)
          .filter((c) => c.status === "pending")
          .map((c) => c.operationId);
        if (pendingOps.length > 0) {
          throw new Error(
            `Refusing to tear down disposable Resource Group while ${pendingOps.length} operation(s) remain "pending" (sample: ${pendingOps.slice(0, 12).join(", ")}). Complete probing or record live-verified blockers via "mark-blocked" so pending === 0, or pass --allow-pending only for emergency abort cleanup.`,
          );
        }
      }
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
        "resource-path": { type: "string" },
        "api-version": { type: "string" },
        "body-json": { type: "string" },
        "body-file": { type: "string" },
      },
    });
    if (!values["work-dir"] || !values.kind) {
      throw new Error("fixture requires --work-dir <dir> and --kind <kind>");
    }
    const customBody = values["body-file"]
      ? (JSON.parse(fs.readFileSync(values["body-file"], "utf8")) as Record<string, unknown>)
      : values["body-json"]
        ? (JSON.parse(values["body-json"]) as Record<string, unknown>)
        : undefined;
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
      customResourcePath: values["resource-path"],
      customApiVersion: values["api-version"],
      customBody,
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
        query: { type: "string" },
        headers: { type: "string" },
        scenario: { type: "string" },
        body: { type: "string" },
        "expect-error": { type: "boolean", default: false },
        "no-poll": { type: "boolean", default: false },
        "max-poll-attempts": { type: "string" },
        "max-poll-duration-ms": { type: "string" },
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
          "probe requires either --request-file <json> or --operation-id <id> (with optional --path <armPath>, --path-params <json>, --query <json>)",
        );
      }
      probeInput = {
        operationId: values["operation-id"],
        ...(values.path ? { pathOrUrl: values.path } : {}),
        ...(values["path-params"]
          ? { pathParams: JSON.parse(values["path-params"]) as Record<string, string> }
          : {}),
        ...(values.query ? { query: JSON.parse(values.query) as Record<string, string> } : {}),
        ...(values.headers
          ? { headers: JSON.parse(values.headers) as Record<string, string> }
          : {}),
        scenario: values.scenario,
        expectError: values["expect-error"],
        pollLro: !values["no-poll"],
        body: values.body ? (JSON.parse(values.body) as unknown) : undefined,
      };
    }
    if (values["max-poll-attempts"]) {
      const parsedAttempts = Number(values["max-poll-attempts"]);
      if (Number.isFinite(parsedAttempts) && parsedAttempts > 0) {
        probeInput.maxPollAttempts = parsedAttempts;
      }
    }
    if (values["max-poll-duration-ms"]) {
      const parsedDuration = Number(values["max-poll-duration-ms"]);
      if (Number.isFinite(parsedDuration) && parsedDuration > 0) {
        probeInput.maxPollDurationMs = parsedDuration;
      }
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

  if (subcommand === "probe-batch") {
    const { values } = parseArgs({
      args: rest,
      options: {
        "work-dir": { type: "string" },
        "batch-file": { type: "string" },
        operations: { type: "string" },
        "continue-on-error": { type: "boolean", default: true },
      },
    });
    if (!values["work-dir"]) {
      throw new Error("probe-batch requires --work-dir <dir>");
    }
    let items: Parameters<typeof executeProbeBatch>[0]["items"];
    if (values["batch-file"]) {
      const parsed = JSON.parse(fs.readFileSync(values["batch-file"], "utf8")) as unknown;
      if (Array.isArray(parsed)) {
        items = parsed as Parameters<typeof executeProbeBatch>[0]["items"];
      } else if (
        parsed &&
        typeof parsed === "object" &&
        Array.isArray((parsed as { probes?: unknown }).probes)
      ) {
        items = (parsed as { probes: Parameters<typeof executeProbeBatch>[0]["items"] }).probes;
      } else {
        throw new Error(
          '--batch-file must contain a JSON array of ProbeRequestInput items (or { "probes": [...] }).',
        );
      }
    } else if (values.operations) {
      items = values.operations
        .split(",")
        .map((s) => s.trim())
        .filter(Boolean)
        .map((operationId) => ({ operationId }));
    } else {
      throw new Error(
        "probe-batch requires either --batch-file <json> or --operations <id1,id2,...>",
      );
    }
    const batchResults = await executeProbeBatch({
      workDir: values["work-dir"],
      items,
      continueOnError: values["continue-on-error"],
    });
    const passed = batchResults.filter((r) => r.probeSucceeded).length;
    console.log(
      JSON.stringify(
        {
          totalItems: batchResults.length,
          succeededItems: passed,
          failedItems: batchResults.length - passed,
          results: batchResults,
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
        "operation-ids": { type: "string" },
        "resource-type": { type: "string" },
        reason: { type: "string" },
      },
    });
    if (
      !values["work-dir"] ||
      !values.reason ||
      (!values["operation-id"] && !values["operation-ids"] && !values["resource-type"])
    ) {
      throw new Error(
        "mark-blocked requires --work-dir <dir> --reason <text> and one of --operation-id <id>, --operation-ids <id1,id2,...>, or --resource-type <Microsoft.Foo/bar>",
      );
    }
    const updatedIds: string[] = [];
    updateLedgerAtomically(values["work-dir"], (locked) => {
      const targetIds = new Set<string>();
      if (values["operation-id"]) {
        targetIds.add(values["operation-id"].trim());
      }
      if (values["operation-ids"]) {
        for (const id of values["operation-ids"]
          .split(",")
          .map((s) => s.trim())
          .filter(Boolean)) {
          targetIds.add(id);
        }
      }
      if (values["resource-type"]) {
        const rtNeedle = values["resource-type"].trim().toLowerCase().replace(/\/+$/, "");
        for (const [opId, op] of Object.entries(locked.operations)) {
          const opRt = op.resourceType.toLowerCase();
          if (opRt === rtNeedle || opRt.startsWith(`${rtNeedle}/`)) {
            targetIds.add(opId);
          }
        }
      }
      if (targetIds.size === 0) {
        throw new Error(
          `No operations matched ${values["operation-id"] ?? values["operation-ids"] ?? values["resource-type"] ?? ""}`,
        );
      }
      for (const id of targetIds) {
        const cov = locked.coverage[id];
        if (!cov) {
          throw new Error(`Unknown operationId "${id}"`);
        }
        if (cov.status !== "passed" && cov.status !== "passed_with_mismatch") {
          cov.status = "blocked";
          cov.blockerReason = values.reason!;
          updatedIds.push(id);
        }
      }
    });
    console.log(
      JSON.stringify(
        {
          markedBlockedCount: updatedIds.length,
          operationIds: updatedIds,
          reason: values.reason,
        },
        null,
        2,
      ),
    );
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
    if (values["write-to-spec"] && values["skip-schema-check"]) {
      throw new Error(
        "Cannot combine --write-to-spec with --skip-schema-check: examples promoted into the TypeSpec project must pass TypeSpec validation.",
      );
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

const MIN_TYPESPEC_V8_HEAP_BYTES = 7 * 1024 * 1024 * 1024;
const TYPESPEC_HEAVY_SUBCOMMANDS = new Set([
  "discover",
  "probe",
  "probe-batch",
  "generate-examples",
  "report",
]);

if (import.meta.main) {
  const sub = process.argv[2] ?? "";
  const heapLimit = v8.getHeapStatistics().heap_size_limit;
  if (
    TYPESPEC_HEAVY_SUBCOMMANDS.has(sub) &&
    heapLimit < MIN_TYPESPEC_V8_HEAP_BYTES &&
    process.env.__ARM_BBX_HEAP_ESCALATED !== "1"
  ) {
    const filteredExecArgv = process.execArgv.filter(
      (arg) => !arg.startsWith("--max-old-space-size"),
    );
    const child = spawnSync(
      process.execPath,
      [...filteredExecArgv, "--max-old-space-size=8192", ...process.argv.slice(1)],
      {
        stdio: "inherit",
        env: { ...process.env, __ARM_BBX_HEAP_ESCALATED: "1" },
      },
    );
    if (child.error) {
      console.error(child.error.message);
      process.exitCode = 1;
    } else {
      process.exitCode = child.status ?? 1;
    }
  } else {
    runCli(process.argv.slice(2)).catch((err: unknown) => {
      console.error(err instanceof Error ? err.message : String(err));
      process.exitCode = 1;
    });
  }
}
