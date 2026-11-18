import * as fs from "node:fs";
import * as path from "node:path";
import type { CoverageLedger, ProbeTrace } from "./types.ts";

export const LEDGER_FILENAME = "coverage-ledger.json";
export const TRACES_DIRNAME = "traces";
export const GENERATED_EXAMPLES_DIRNAME = "examples";

export function getLedgerPath(workDir: string): string {
  return path.join(workDir, LEDGER_FILENAME);
}

export function loadLedger(workDir: string): CoverageLedger {
  const ledgerPath = getLedgerPath(workDir);
  if (!fs.existsSync(ledgerPath)) {
    throw new Error(
      `Coverage ledger not found at ${ledgerPath}. Run the "discover" command first.`,
    );
  }
  return JSON.parse(fs.readFileSync(ledgerPath, "utf8")) as CoverageLedger;
}

export function saveLedger(workDir: string, ledger: CoverageLedger): void {
  fs.mkdirSync(workDir, { recursive: true });
  ledger.updatedAt = new Date().toISOString();
  fs.writeFileSync(getLedgerPath(workDir), `${JSON.stringify(ledger, null, 2)}\n`, "utf8");
}

export function saveProbeTrace(workDir: string, trace: ProbeTrace): string {
  const tracesDir = path.join(workDir, TRACES_DIRNAME);
  fs.mkdirSync(tracesDir, { recursive: true });
  const safeOpId = trace.operationId.replace(/[^a-zA-Z0-9_-]/g, "_");
  const safeScenario = trace.scenario.replace(/[^a-zA-Z0-9_-]/g, "_");
  const filename = `${String(trace.sequence).padStart(3, "0")}-${safeOpId}-${safeScenario}.json`;
  const fullPath = path.join(tracesDir, filename);
  fs.writeFileSync(fullPath, `${JSON.stringify(trace, null, 2)}\n`, "utf8");
  return fullPath;
}

export function loadAllProbeTraces(workDir: string): ProbeTrace[] {
  const tracesDir = path.join(workDir, TRACES_DIRNAME);
  if (!fs.existsSync(tracesDir)) {
    return [];
  }
  const files = fs
    .readdirSync(tracesDir)
    .filter((name) => name.endsWith(".json"))
    .sort();
  return files.map(
    (name) => JSON.parse(fs.readFileSync(path.join(tracesDir, name), "utf8")) as ProbeTrace,
  );
}

export function nextTraceSequence(workDir: string): number {
  const tracesDir = path.join(workDir, TRACES_DIRNAME);
  if (!fs.existsSync(tracesDir)) {
    return 1;
  }
  const existing = fs.readdirSync(tracesDir).filter((name) => name.endsWith(".json"));
  return existing.length + 1;
}
