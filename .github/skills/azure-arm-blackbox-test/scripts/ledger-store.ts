import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type { CoverageLedger, ProbeTrace } from "./types.ts";

export const LEDGER_FILENAME = "coverage-ledger.json";
export const TRACES_DIRNAME = "traces";
export const GENERATED_EXAMPLES_DIRNAME = "examples";

function writeFileAtomicallySync(targetPath: string, content: string): void {
  const parentDir = path.dirname(targetPath);
  fs.mkdirSync(parentDir, { recursive: true });
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try {
    fs.writeFileSync(tmpPath, content, "utf8");
    fs.renameSync(tmpPath, targetPath);
  } catch (err) {
    try {
      fs.rmSync(tmpPath, { force: true });
    } catch {
      // Ignore best-effort temp cleanup error.
    }
    throw err;
  }
}

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
  ledger.updatedAt = new Date().toISOString();
  writeFileAtomicallySync(getLedgerPath(workDir), `${JSON.stringify(ledger, null, 2)}\n`);
}

export function saveProbeTrace(workDir: string, trace: ProbeTrace): string {
  const tracesDir = path.join(workDir, TRACES_DIRNAME);
  const safeOpId = trace.operationId.replace(/[^a-zA-Z0-9_-]/g, "_");
  const safeScenario = trace.scenario.replace(/[^a-zA-Z0-9_-]/g, "_");
  const filename = `${String(trace.sequence).padStart(3, "0")}-${safeOpId}-${safeScenario}.json`;
  const fullPath = path.join(tracesDir, filename);
  writeFileAtomicallySync(fullPath, `${JSON.stringify(trace, null, 2)}\n`);
  return fullPath;
}

function parseTraceSequenceNumber(filename: string): number {
  const m = /^(\d+)-/.exec(filename);
  return m ? Number(m[1]) : Number.MAX_SAFE_INTEGER;
}

export function loadAllProbeTraces(workDir: string): ProbeTrace[] {
  const tracesDir = path.join(workDir, TRACES_DIRNAME);
  if (!fs.existsSync(tracesDir)) {
    return [];
  }
  // Sort numerically by sequence prefix so trace 1000-... sorts after 999-... (#4322)!
  const files = fs
    .readdirSync(tracesDir)
    .filter((name) => name.endsWith(".json"))
    .sort((a, b) => {
      const diff = parseTraceSequenceNumber(a) - parseTraceSequenceNumber(b);
      return diff !== 0 ? diff : a.localeCompare(b);
    });
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
  let maxSeq = 0;
  for (const name of existing) {
    const seq = parseTraceSequenceNumber(name);
    if (Number.isFinite(seq) && seq !== Number.MAX_SAFE_INTEGER && seq > maxSeq) {
      maxSeq = seq;
    }
  }
  return Math.max(maxSeq, existing.length) + 1;
}
