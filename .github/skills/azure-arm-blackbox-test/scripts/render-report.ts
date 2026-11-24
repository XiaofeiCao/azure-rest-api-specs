import * as fs from "node:fs";
import * as path from "node:path";
import { analyzeBehavioralDiscrepancies } from "./analyze-behavior.ts";
import {
  GENERATED_EXAMPLES_DIRNAME,
  loadAllProbeTraces,
  loadLedger,
  saveLedger,
} from "./ledger-store.ts";
import type { BehavioralDiscrepancy, CoverageLedger } from "./types.ts";

export interface BlackboxSummaryReport {
  generatedAt: string;
  serviceName: string;
  providerNamespace: string;
  apiVersion: string;
  availableApiVersions: string[];
  typespecProjectDir: string;
  entrypointFile: string;
  disposableResourceGroup?: CoverageLedger["disposableResourceGroup"];
  coverageSummary: {
    totalOperations: number;
    testedOperations: number;
    coveragePercent: number;
    passedClean: number;
    passedWithMismatch: number;
    failedServiceError: number;
    blocked: number;
    pending: number;
  };
  discrepancySummary: {
    total: number;
    blocking: number;
    warning: number;
    info: number;
    byRule: Record<string, number>;
  };
  discrepancies: BehavioralDiscrepancy[];
  operations: Array<{
    operationId: string;
    method: string;
    pathTemplate: string;
    sourceLocation?: string;
    phase: string;
    status: string;
    attempts: number;
    lastHttpStatus?: number;
    discrepancyCount: number;
    generatedExamplesCount: number;
    blockerReason?: string;
  }>;
  generatedExampleFiles: string[];
}

function formatSourceLoc(
  typespecProjectDir: string,
  loc: BehavioralDiscrepancy["sourceLocation"],
): string | undefined {
  if (!loc) {
    return undefined;
  }
  const rel = path.relative(typespecProjectDir, loc.file).replace(/\\/g, "/");
  return `${rel}:${loc.line}`;
}

export async function buildSummaryReport(workDir: string): Promise<{
  jsonPath: string;
  markdownPath: string;
  report: BlackboxSummaryReport;
}> {
  const { runTypeSpecLiveValidation } = await import("./analyze-behavior.ts");
  const ledger = loadLedger(workDir);
  const traces = loadAllProbeTraces(workDir);

  // Deduplicate discrepancies by (operationId, ruleId, summary), re-evaluating TypeSpec schema + behavioral rules across saved traces.
  const dedupedDiscrepancies = new Map<string, BehavioralDiscrepancy>();
  const perOpDiscrepancyCounts = new Map<string, number>();
  for (const trace of traces) {
    const contract = ledger.operations[trace.operationId];
    let recomputed: BehavioralDiscrepancy[] = [];
    if (contract && trace.exchanges[0]) {
      const reqErrs =
        trace.requestSchemaErrors ??
        (
          await runTypeSpecLiveValidation(
            ledger.typespecProjectDir,
            ledger.apiVersion,
            contract.operationId,
            trace.exchanges[0],
          )
        ).requestErrors;
      const respErrs =
        trace.responseSchemaErrors ??
        (
          await runTypeSpecLiveValidation(
            ledger.typespecProjectDir,
            ledger.apiVersion,
            contract.operationId,
            trace.exchanges[0],
          )
        ).responseErrors;
      recomputed = analyzeBehavioralDiscrepancies({
        contract,
        expectError: trace.expectError,
        exchanges: trace.exchanges,
        observedLro: trace.observedLro,
        requestSchemaErrors: reqErrs,
        responseSchemaErrors: respErrs,
      });
    }
    for (const d of [...trace.discrepancies, ...recomputed]) {
      if (!d.sourceLocation && contract?.sourceLocation) {
        d.sourceLocation = contract.sourceLocation;
      }
      const key = `${d.operationId}::${d.ruleId}::${d.summary}`;
      if (!dedupedDiscrepancies.has(key)) {
        dedupedDiscrepancies.set(key, d);
        perOpDiscrepancyCounts.set(
          d.operationId,
          (perOpDiscrepancyCounts.get(d.operationId) ?? 0) + 1,
        );
      }
    }
  }
  for (const [opId, count] of perOpDiscrepancyCounts.entries()) {
    const entry = ledger.coverage[opId];
    if (entry) {
      entry.discrepancyCount = Math.max(entry.discrepancyCount, count);
      if (entry.status === "passed" && entry.discrepancyCount > 0) {
        entry.status = "passed_with_mismatch";
      }
    }
  }
  saveLedger(workDir, ledger);
  const discrepancies = [...dedupedDiscrepancies.values()];

  const byRule: Record<string, number> = {};
  let blocking = 0;
  let warning = 0;
  let info = 0;
  for (const d of discrepancies) {
    byRule[d.ruleId] = (byRule[d.ruleId] ?? 0) + 1;
    if (d.severity === "blocking") blocking++;
    else if (d.severity === "warning") warning++;
    else info++;
  }

  const orderedEntries = ledger.executionOrder.map((opId) => ledger.coverage[opId]);
  const totalOperations = orderedEntries.length;
  const passedClean = orderedEntries.filter((e) => e.status === "passed").length;
  const passedWithMismatch = orderedEntries.filter(
    (e) => e.status === "passed_with_mismatch",
  ).length;
  const failedServiceError = orderedEntries.filter(
    (e) => e.status === "failed_service_error",
  ).length;
  const blocked = orderedEntries.filter((e) => e.status === "blocked").length;
  const pending = orderedEntries.filter(
    (e) => e.status === "pending" || e.status === "skipped",
  ).length;
  const testedOperations = passedClean + passedWithMismatch;
  const coveragePercent =
    totalOperations === 0 ? 100 : Number(((testedOperations / totalOperations) * 100).toFixed(1));

  const examplesDir = path.join(workDir, GENERATED_EXAMPLES_DIRNAME, ledger.apiVersion);
  const generatedExampleFiles = fs.existsSync(examplesDir)
    ? fs
        .readdirSync(examplesDir)
        .filter((f) => f.endsWith(".json"))
        .sort()
        .map((f) => path.join(examplesDir, f))
    : [];

  const report: BlackboxSummaryReport = {
    generatedAt: new Date().toISOString(),
    serviceName: ledger.serviceName,
    providerNamespace: ledger.providerNamespace,
    apiVersion: ledger.apiVersion,
    availableApiVersions: ledger.availableApiVersions,
    typespecProjectDir: ledger.typespecProjectDir,
    entrypointFile: ledger.entrypointFile,
    disposableResourceGroup: ledger.disposableResourceGroup,
    coverageSummary: {
      totalOperations,
      testedOperations,
      coveragePercent,
      passedClean,
      passedWithMismatch,
      failedServiceError,
      blocked,
      pending,
    },
    discrepancySummary: {
      total: discrepancies.length,
      blocking,
      warning,
      info,
      byRule,
    },
    discrepancies,
    operations: orderedEntries.map((e) => ({
      operationId: e.operationId,
      method: e.method,
      pathTemplate: e.pathTemplate,
      sourceLocation: formatSourceLoc(ledger.typespecProjectDir, e.sourceLocation),
      phase: e.phase,
      status: e.status,
      attempts: e.attempts,
      lastHttpStatus: e.lastHttpStatus,
      discrepancyCount: e.discrepancyCount,
      generatedExamplesCount: e.generatedExamples.length,
      blockerReason: e.blockerReason,
    })),
    generatedExampleFiles,
  };

  const jsonPath = path.join(workDir, "blackbox-report.json");
  const markdownPath = path.join(workDir, "blackbox-report.md");
  fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
  fs.writeFileSync(markdownPath, renderMarkdownReport(report), "utf8");

  return { jsonPath, markdownPath, report };
}

function renderMarkdownReport(report: BlackboxSummaryReport): string {
  const lines: string[] = [];
  lines.push(
    `# ARM TypeSpec Blackbox Report: \`${report.providerNamespace}\` (\`${report.apiVersion}\`)`,
  );
  lines.push("");
  lines.push(`- **Generated at**: ${report.generatedAt}`);
  lines.push(`- **TypeSpec Project**: \`${report.typespecProjectDir}\``);
  lines.push(
    `- **API Coverage**: **${report.coverageSummary.testedOperations} / ${report.coverageSummary.totalOperations} (${report.coverageSummary.coveragePercent}%)**`,
  );
  lines.push(
    `  - Passed cleanly: ${report.coverageSummary.passedClean} | Passed with spec mismatch: ${report.coverageSummary.passedWithMismatch} | Service error: ${report.coverageSummary.failedServiceError} | Blocked: ${report.coverageSummary.blocked} | Untested: ${report.coverageSummary.pending}`,
  );
  lines.push(
    `- **Behavioral Discrepancies**: **${report.discrepancySummary.total}** (Blocking: ${report.discrepancySummary.blocking}, Warning: ${report.discrepancySummary.warning}, Info: ${report.discrepancySummary.info})`,
  );
  lines.push(`- **Generated Sanitized Examples**: **${report.generatedExampleFiles.length}**`);
  if (report.disposableResourceGroup) {
    lines.push(
      `- **Disposable Test RG**: \`${report.disposableResourceGroup.name}\` (${report.disposableResourceGroup.location}) — cleanup status: **\`${report.disposableResourceGroup.cleanupStatus}\`**`,
    );
  }
  lines.push("");

  lines.push("## 1. TypeSpec-vs-Service Behavioral Discrepancies");
  lines.push("");
  if (report.discrepancies.length === 0) {
    lines.push(
      "No TypeSpec-vs-service behavioral discrepancies were detected across tested operations.",
    );
    lines.push("");
  } else {
    for (const d of report.discrepancies) {
      const badge =
        d.severity === "blocking"
          ? "[BLOCKING]"
          : d.severity === "warning"
            ? "[WARNING]"
            : "[INFO]";
      const locLabel = formatSourceLoc(report.typespecProjectDir, d.sourceLocation);
      lines.push(
        `### ${badge} \`${d.ruleId}\` — \`${d.operationId}\`${locLabel ? ` (\`${locLabel}\`)` : ""}`,
      );
      lines.push("");
      lines.push(`- **Summary**: ${d.summary}`);
      lines.push(`- **TypeSpec Expectation**: ${d.specExpectation}`);
      lines.push(`- **Actual Live Behavior**: ${d.actualWireBehavior}`);
      lines.push("");
    }
  }

  lines.push("## 2. Operation Coverage Matrix");
  lines.push("");
  lines.push(
    "| Operation ID | TypeSpec Source | Method | Phase | Status | HTTP | Discrepancies | Examples | Notes |",
  );
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const op of report.operations) {
    const note = op.blockerReason
      ? op.blockerReason
          .slice(0, 100)
          .replace(/\\/g, "\\\\")
          .replace(/\|/g, "\\|")
          .replace(/\r?\n/g, " ")
      : "";
    lines.push(
      `| \`${op.operationId}\` | ${op.sourceLocation ? `\`${op.sourceLocation}\`` : "-"} | \`${op.method}\` | ${op.phase} | \`${op.status}\` | ${op.lastHttpStatus ?? "-"} | ${op.discrepancyCount} | ${op.generatedExamplesCount} | ${note} |`,
    );
  }
  lines.push("");

  lines.push("## 3. Generated Real-Life Examples");
  lines.push("");
  if (report.generatedExampleFiles.length === 0) {
    lines.push("No example files generated yet.");
  } else {
    for (const exFile of report.generatedExampleFiles) {
      lines.push(`- \`${path.basename(exFile)}\` (\`${exFile}\`)`);
    }
  }
  lines.push("");

  return lines.join("\n");
}
