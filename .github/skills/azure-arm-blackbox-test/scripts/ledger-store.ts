import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";
import type {
  CoverageLedger,
  DisposableResourceGroupState,
  OperationCoverageEntry,
  OperationCoverageStatus,
  ProbeTrace,
  ShardPartitionManifest,
} from "./types.ts";

export const LEDGER_FILENAME = "coverage-ledger.json";
export const TRACES_DIRNAME = "traces";
export const GENERATED_EXAMPLES_DIRNAME = "examples";

const WINDOWS_RENAME_RETRY_DELAYS_MS = [15, 30, 60, 120, 200, 300, 400, 500];
const LOCK_ACQUIRE_TIMEOUT_MS = 30_000;
const STALE_LOCK_MAX_AGE_MS = 60_000;
const RENAME_WAIT_ARRAY = new Int32Array(new SharedArrayBuffer(4));
const activeLockDepthByPath = new Map<string, number>();

function sleepSyncMs(ms: number): void {
  Atomics.wait(RENAME_WAIT_ARRAY, 0, 0, ms);
}

function isProcessAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException | undefined)?.code;
    return code === "EPERM";
  }
}

export function withLedgerLockSync<T>(workDir: string, fn: () => T): T {
  const resolvedWorkDir = path.resolve(workDir);
  fs.mkdirSync(resolvedWorkDir, { recursive: true });
  const lockPath = path.join(resolvedWorkDir, `${LEDGER_FILENAME}.lock`);
  const existingDepth = activeLockDepthByPath.get(lockPath) ?? 0;
  if (existingDepth > 0) {
    activeLockDepthByPath.set(lockPath, existingDepth + 1);
    try {
      return fn();
    } finally {
      activeLockDepthByPath.set(lockPath, existingDepth);
    }
  }

  const deadline = Date.now() + LOCK_ACQUIRE_TIMEOUT_MS;
  let acquired = false;
  while (!acquired) {
    try {
      const fd = fs.openSync(lockPath, "wx");
      try {
        fs.writeFileSync(fd, JSON.stringify({ pid: process.pid, createdAt: Date.now() }), "utf8");
      } finally {
        fs.closeSync(fd);
      }
      acquired = true;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException | undefined)?.code;
      if (code !== "EEXIST" && code !== "EPERM" && code !== "EACCES") {
        throw err;
      }
      try {
        const raw = fs.readFileSync(lockPath, "utf8");
        const parsed = JSON.parse(raw) as { pid?: number; createdAt?: number };
        const ageMs = Date.now() - (parsed.createdAt ?? 0);
        if ((parsed.pid && !isProcessAlive(parsed.pid)) || ageMs > STALE_LOCK_MAX_AGE_MS) {
          fs.rmSync(lockPath, { force: true });
          continue;
        }
      } catch {
        // Lock file may have just been released or still being written; fall through to backoff.
      }
      if (Date.now() >= deadline) {
        throw new Error(
          `Timed out after ${LOCK_ACQUIRE_TIMEOUT_MS}ms waiting for ledger lock "${lockPath}".`,
          { cause: err },
        );
      }
      sleepSyncMs(20 + Math.floor(Math.random() * 40));
    }
  }

  activeLockDepthByPath.set(lockPath, 1);
  try {
    return fn();
  } finally {
    activeLockDepthByPath.delete(lockPath);
    try {
      fs.rmSync(lockPath, { force: true });
    } catch {
      // Ignore best-effort lock removal error.
    }
  }
}

export function updateLedgerAtomically(
  workDir: string,
  mutator: (ledger: CoverageLedger) => void,
): CoverageLedger {
  return withLedgerLockSync(workDir, () => {
    const fresh = loadLedger(workDir);
    mutator(fresh);
    saveLedger(workDir, fresh);
    return fresh;
  });
}

function writeFileAtomicallySync(targetPath: string, content: string): void {
  const parentDir = path.dirname(targetPath);
  fs.mkdirSync(parentDir, { recursive: true });
  const tmpPath = `${targetPath}.${process.pid}.${crypto.randomUUID()}.tmp`;
  try {
    fs.writeFileSync(tmpPath, content, "utf8");
    let lastRenameErr: unknown;
    for (let attempt = 0; attempt <= WINDOWS_RENAME_RETRY_DELAYS_MS.length; attempt++) {
      try {
        fs.renameSync(tmpPath, targetPath);
        return;
      } catch (err) {
        lastRenameErr = err;
        const code = (err as NodeJS.ErrnoException | undefined)?.code;
        const isTransientLock = code === "EPERM" || code === "EBUSY" || code === "EACCES";
        if (!isTransientLock || attempt === WINDOWS_RENAME_RETRY_DELAYS_MS.length) {
          throw err;
        }
        sleepSyncMs(WINDOWS_RENAME_RETRY_DELAYS_MS[attempt]);
      }
    }
    throw lastRenameErr;
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
  withLedgerLockSync(workDir, () => {
    ledger.updatedAt = new Date().toISOString();
    writeFileAtomicallySync(getLedgerPath(workDir), `${JSON.stringify(ledger, null, 2)}\n`);
  });
}

export function saveProbeTrace(workDir: string, trace: ProbeTrace): string {
  return withLedgerLockSync(workDir, () => {
    const tracesDir = path.join(workDir, TRACES_DIRNAME);
    fs.mkdirSync(tracesDir, { recursive: true });
    const safeOpId = trace.operationId.replace(/[^a-zA-Z0-9_-]/g, "_");
    const safeScenario = trace.scenario.replace(/[^a-zA-Z0-9_-]/g, "_");
    const existingFiles = fs.readdirSync(tracesDir).filter((name) => name.endsWith(".json"));
    const requestedPrefix = `${String(trace.sequence).padStart(3, "0")}-`;
    const collidesWithExistingSeq = existingFiles.some((name) => name.startsWith(requestedPrefix));
    if (collidesWithExistingSeq) {
      trace.sequence = nextTraceSequence(workDir);
    }
    const finalFilename = `${String(trace.sequence).padStart(3, "0")}-${safeOpId}-${safeScenario}.json`;
    const fullPath = path.join(tracesDir, finalFilename);
    writeFileAtomicallySync(fullPath, `${JSON.stringify(trace, null, 2)}\n`);
    return fullPath;
  });
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

const COVERAGE_STATUS_RANK: Record<OperationCoverageStatus, number> = {
  pending: 0,
  skipped: 1,
  blocked: 2,
  failed_service_error: 3,
  passed: 4,
  passed_with_mismatch: 5,
};

export function mergeShardWorkDirs(options: {
  parentWorkDir: string;
  shardDirs?: string[];
  allowActiveShardRgs?: boolean;
}): {
  mergedShards: number;
  totalOperations: number;
  pendingOperations: number;
  mergedTraces: number;
  mergedExamples: number;
} {
  const parentWorkDir = path.resolve(options.parentWorkDir);
  const parentLedger = loadLedger(parentWorkDir);
  const manifestPath = path.join(parentWorkDir, "shard-manifest.json");
  let manifest: ShardPartitionManifest | undefined;
  if (fs.existsSync(manifestPath)) {
    manifest = JSON.parse(fs.readFileSync(manifestPath, "utf8")) as ShardPartitionManifest;
  }

  const shardEntries: Array<{ shardId: string; workDir: string; primaryRts: Set<string> }> =
    options.shardDirs && options.shardDirs.length > 0
      ? options.shardDirs.map((dir, idx) => ({
          shardId: path.basename(dir) || `shard-${String(idx + 1).padStart(2, "0")}`,
          workDir: path.resolve(dir),
          primaryRts: new Set<string>(),
        }))
      : (manifest?.shards ?? []).map((s) => ({
          shardId: s.shardId,
          workDir: path.resolve(s.workDir),
          primaryRts: new Set<string>(s.resourceTypes),
        }));

  if (shardEntries.length === 0) {
    throw new Error(
      `No shards found to merge in "${parentWorkDir}". Run "partition-shards" first or pass --shard-dir.`,
    );
  }

  const loadedShards = shardEntries.map((entry) => {
    const ledger = loadLedger(entry.workDir);
    const rg = ledger.disposableResourceGroup;
    if (
      !options.allowActiveShardRgs &&
      rg &&
      rg.cleanupStatus !== "deleted" &&
      rg.cleanupStatus !== "not_created"
    ) {
      throw new Error(
        `Refusing to merge shard "${entry.shardId}" ("${entry.workDir}") while its disposable Resource Group "${rg.name}" has cleanupStatus "${rg.cleanupStatus}". Delete all shard RGs first.`,
      );
    }
    const traces = loadAllProbeTraces(entry.workDir);
    return { ...entry, ledger, traces };
  });

  // Pick the winning shard per operationId so prerequisite helper creates/deletes that ran in multiple shards
  // do not duplicate discrepancies or overwrite primary examples.
  const winningShardByOp = new Map<string, (typeof loadedShards)[number]>();
  for (const opId of Object.keys(parentLedger.operations)) {
    const opContract = parentLedger.operations[opId];
    let best: (typeof loadedShards)[number] | undefined;
    let bestScore = -1;
    for (const shard of loadedShards) {
      const cov = shard.ledger.coverage[opId];
      if (!cov) continue;
      const rank = COVERAGE_STATUS_RANK[cov.status] ?? 0;
      const isPrimaryOwner =
        shard.primaryRts.size === 0 || shard.primaryRts.has(opContract.resourceType) ? 1 : 0;
      // Primary score = status rank * 10 + ownership tie-breaker.
      const score = rank * 10 + isPrimaryOwner;
      if (score > bestScore) {
        bestScore = score;
        best = shard;
      }
    }
    if (best) {
      winningShardByOp.set(opId, best);
    }
  }

  const parentTracesDir = path.join(parentWorkDir, TRACES_DIRNAME);
  const parentExamplesDir = path.join(
    parentWorkDir,
    GENERATED_EXAMPLES_DIRNAME,
    parentLedger.apiVersion,
  );
  fs.rmSync(parentTracesDir, { recursive: true, force: true });
  fs.mkdirSync(parentTracesDir, { recursive: true });
  fs.mkdirSync(parentExamplesDir, { recursive: true });

  let seq = 1;
  let mergedExamplesCount = 0;
  const newTraceFilesByOp = new Map<string, string[]>();
  const newExamplesByOp = new Map<string, string[]>();

  for (const shard of loadedShards) {
    for (const trace of shard.traces) {
      if (winningShardByOp.get(trace.operationId) !== shard) {
        continue;
      }
      const cloned: ProbeTrace = { ...trace, sequence: seq++ };
      const savedPath = saveProbeTrace(parentWorkDir, cloned);
      const list = newTraceFilesByOp.get(trace.operationId) ?? [];
      list.push(savedPath);
      newTraceFilesByOp.set(trace.operationId, list);
    }

    const shardExamplesApiDir = path.join(
      shard.workDir,
      GENERATED_EXAMPLES_DIRNAME,
      parentLedger.apiVersion,
    );
    if (fs.existsSync(shardExamplesApiDir)) {
      for (const exFile of fs.readdirSync(shardExamplesApiDir)) {
        if (!exFile.endsWith(".json")) continue;
        const srcPath = path.join(shardExamplesApiDir, exFile);
        try {
          const parsed = JSON.parse(fs.readFileSync(srcPath, "utf8")) as {
            operationId?: string;
          };
          if (parsed.operationId && winningShardByOp.get(parsed.operationId) !== shard) {
            continue;
          }
          const destPath = path.join(parentExamplesDir, exFile);
          fs.copyFileSync(srcPath, destPath);
          mergedExamplesCount++;
          if (parsed.operationId) {
            const exList = newExamplesByOp.get(parsed.operationId) ?? [];
            if (!exList.includes(destPath)) exList.push(destPath);
            newExamplesByOp.set(parsed.operationId, exList);
          }
        } catch {
          // Ignore unreadable example JSON.
        }
      }
    }
  }

  const mergedRgs: DisposableResourceGroupState[] = [];
  for (const shard of loadedShards) {
    if (shard.ledger.disposableResourceGroup) {
      mergedRgs.push(shard.ledger.disposableResourceGroup);
    }
    for (const fix of shard.ledger.provisionedFixtures) {
      if (
        !parentLedger.provisionedFixtures.some((existing) => existing.resourceId === fix.resourceId)
      ) {
        parentLedger.provisionedFixtures.push(fix);
      }
    }
  }

  for (const opId of Object.keys(parentLedger.coverage)) {
    const winner = winningShardByOp.get(opId);
    if (!winner) continue;
    const winCov: OperationCoverageEntry | undefined = winner.ledger.coverage[opId];
    if (!winCov) continue;
    parentLedger.coverage[opId] = {
      ...winCov,
      traceFiles: newTraceFilesByOp.get(opId) ?? [],
      generatedExamples: newExamplesByOp.get(opId) ?? [],
    };
  }

  if (mergedRgs.length > 0) {
    parentLedger.mergedShardResourceGroups = mergedRgs;
    if (!parentLedger.disposableResourceGroup) {
      parentLedger.disposableResourceGroup = mergedRgs[0];
    }
  }

  saveLedger(parentWorkDir, parentLedger);
  const pendingOperations = Object.values(parentLedger.coverage).filter(
    (c) => c.status === "pending",
  ).length;
  return {
    mergedShards: loadedShards.length,
    totalOperations: Object.keys(parentLedger.coverage).length,
    pendingOperations,
    mergedTraces: seq - 1,
    mergedExamples: mergedExamplesCount,
  };
}
