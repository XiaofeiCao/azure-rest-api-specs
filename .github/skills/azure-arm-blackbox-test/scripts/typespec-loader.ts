import * as fs from "node:fs";
import * as path from "node:path";
import { getArmProviderNamespace } from "@azure-tools/typespec-azure-resource-manager";
import {
  createTCGCContext,
  getLibraryName,
  resolveOperationId as resolveTcgcOperationId,
  type TCGCContext,
} from "@azure-tools/typespec-client-generator-core";
import {
  compile,
  formatDiagnostic,
  getNamespaceFullName,
  getSourceLocation,
  listServices,
  NodeHost,
  resolveCompilerOptions,
  type CompilerHost,
  type ModelProperty,
  type Namespace,
  type Operation,
  type Program,
} from "@typespec/compiler";
import { unsafe_mutateSubgraphWithNamespace } from "@typespec/compiler/experimental";
import { listHttpOperationsIn, type HttpOperation } from "@typespec/http";
import { getOperationId } from "@typespec/openapi";
import { getVersioningMutators } from "@typespec/versioning";
import type { TypeSpecSourceLocation } from "./types.ts";

export interface LoadedTypeSpecService {
  typespecProjectDir: string;
  entrypointFile: string;
  program: Program;
  tcgcContext: TCGCContext;
  serviceNamespace: Namespace;
  projectedNamespace: Namespace;
  providerNamespace: string;
  apiVersion: string;
  availableApiVersions: string[];
  httpOperations: HttpOperation[];
  operationsById: Map<string, HttpOperation>;
}

export function resolveCanonicalOperationId(
  tcgcContext: TCGCContext,
  program: Program,
  operation: Operation,
): string {
  const explicit = getOperationId(program, operation);
  if (explicit) {
    return explicit;
  }
  const tcgcId = resolveTcgcOperationId(tcgcContext, operation, true);
  return tcgcId
    .split("_")
    .map((seg) => (seg.length > 0 ? `${seg[0].toUpperCase()}${seg.slice(1)}` : seg))
    .join("_");
}

export function resolveBodyParameterName(
  tcgcContext: TCGCContext,
  bodyProperty: ModelProperty | undefined,
): string {
  if (!bodyProperty) {
    return "parameters";
  }
  return getLibraryName(tcgcContext, bodyProperty) || bodyProperty.name || "parameters";
}

const loadedServiceCache = new Map<string, Promise<LoadedTypeSpecService>>();

function findTypeSpecProjectsUnder(rootDir: string): string[] {
  const found: string[] = [];
  const queue = [rootDir];
  while (queue.length > 0) {
    const current = queue.shift()!;
    if (
      fs.existsSync(path.join(current, "tspconfig.yaml")) &&
      fs.existsSync(path.join(current, "main.tsp"))
    ) {
      found.push(current);
      continue;
    }
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
      if (
        !entry.isDirectory() ||
        entry.name.startsWith(".") ||
        ["node_modules", "examples", "scenarios", "stable", "preview", "coverage"].includes(
          entry.name,
        )
      ) {
        continue;
      }
      queue.push(path.join(current, entry.name));
    }
  }
  return found.sort();
}

export function resolveTypeSpecProject(specInputPath: string): {
  typespecProjectDir: string;
  entrypointFile: string;
} {
  const resolved = path.resolve(specInputPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`TypeSpec path does not exist: ${resolved}`);
  }

  if (fs.statSync(resolved).isFile()) {
    if (!resolved.endsWith(".tsp") && path.basename(resolved) !== "tspconfig.yaml") {
      throw new Error(
        `Purely TypeSpec-native mode requires a TypeSpec project directory or .tsp/tspconfig.yaml file; got: ${resolved}`,
      );
    }
    const dir = path.dirname(resolved);
    const entrypoint = resolved.endsWith(".tsp") ? resolved : path.join(dir, "main.tsp");
    if (!fs.existsSync(entrypoint)) {
      throw new Error(`TypeSpec entrypoint main.tsp not found in ${dir}`);
    }
    return { typespecProjectDir: dir, entrypointFile: entrypoint };
  }

  // Check current or ancestor directories first.
  let cursor: string | undefined = resolved;
  while (cursor) {
    if (
      fs.existsSync(path.join(cursor, "tspconfig.yaml")) &&
      fs.existsSync(path.join(cursor, "main.tsp"))
    ) {
      return {
        typespecProjectDir: cursor,
        entrypointFile: path.join(cursor, "main.tsp"),
      };
    }
    const parent = path.dirname(cursor);
    if (parent === cursor || path.basename(cursor) === "specification") {
      break;
    }
    cursor = parent;
  }

  // Search child directories (preferring ARM resource-manager / .Management projects).
  const candidates = findTypeSpecProjectsUnder(resolved);
  if (candidates.length === 0) {
    throw new Error(
      `No TypeSpec project (tspconfig.yaml + main.tsp) found under ${resolved}. Swagger-only directories are not supported in TypeSpec-native mode.`,
    );
  }

  const armCandidates = candidates.filter((dir) => {
    const norm = dir.replace(/\\/g, "/");
    return norm.includes("/resource-manager/") || norm.endsWith(".Management");
  });
  const pool = armCandidates.length > 0 ? armCandidates : candidates;
  if (pool.length > 1) {
    throw new Error(
      `Ambiguous TypeSpec root "${resolved}" contains ${pool.length} TypeSpec projects:\n` +
        pool.map((p) => `  - ${p}`).join("\n") +
        "\nPass the specific TypeSpec project directory via --spec.",
    );
  }
  const selected = pool[0];
  return {
    typespecProjectDir: selected,
    entrypointFile: path.join(selected, "main.tsp"),
  };
}

export function extractOperationSourceLocation(op: Operation): TypeSpecSourceLocation | undefined {
  const loc = getSourceLocation(op, { locateId: true });
  if (!loc || !loc.file) {
    return undefined;
  }
  const lineAndChar = loc.file.getLineAndCharacterOfPosition(loc.pos);
  return {
    file: path.normalize(loc.file.path),
    line: lineAndChar.line + 1,
    column: lineAndChar.character + 1,
  };
}

export async function loadProjectedTypeSpecService(
  specInputPath: string,
  requestedApiVersion?: string,
): Promise<LoadedTypeSpecService> {
  const { typespecProjectDir, entrypointFile } = resolveTypeSpecProject(specInputPath);
  const cacheKey = `${entrypointFile}::${requestedApiVersion ?? "<latest>"}`;
  const cached = loadedServiceCache.get(cacheKey);
  if (cached) {
    return cached;
  }

  const loadPromise = (async (): Promise<LoadedTypeSpecService> => {
    const host: CompilerHost = {
      ...NodeHost,
      logSink: {
        log: () => {
          // Keep compiler logs quiet during structured CLI invocations.
        },
      },
    };

    const [compilerOptions, optionDiagnostics] = await resolveCompilerOptions(host, {
      cwd: typespecProjectDir,
      entrypoint: entrypointFile,
      overrides: {
        emit: [],
      },
    });

    const fatalOptionErrors = optionDiagnostics.filter((d) => d.severity === "error");
    if (fatalOptionErrors.length > 0) {
      const formatted = fatalOptionErrors.map((d) => formatDiagnostic(d)).join("\n");
      throw new Error(`Failed to resolve TypeSpec compiler options:\n${formatted}`);
    }

    const program = await compile(host, entrypointFile, {
      ...compilerOptions,
      noEmit: true,
      linterRuleSet: { enable: {}, disable: {} },
    });

    if (program.hasError()) {
      const errors = program.diagnostics
        .filter((d) => d.severity === "error")
        .map((d) => formatDiagnostic(d))
        .join("\n");
      throw new Error(`TypeSpec compilation failed for ${entrypointFile}:\n${errors}`);
    }

    const services = listServices(program);
    if (services.length === 0) {
      throw new Error(`No @service namespace declared in ${entrypointFile}.`);
    }
    const service = services[0];
    const serviceNamespace = service.type;
    const rawNamespaceName = getNamespaceFullName(serviceNamespace);

    const versioningMutators = getVersioningMutators(program, serviceNamespace);
    let projectedNamespace: Namespace = serviceNamespace;
    let selectedApiVersion: string;
    let availableApiVersions: string[];

    if (versioningMutators?.kind === "versioned") {
      availableApiVersions = versioningMutators.snapshots.map((s) => s.version.value);
      if (availableApiVersions.length === 0) {
        throw new Error(`@versioned namespace ${rawNamespaceName} defines zero versions.`);
      }
      const chosenVersion =
        requestedApiVersion ?? availableApiVersions[availableApiVersions.length - 1];
      const snapshot = versioningMutators.snapshots.find((s) => s.version.value === chosenVersion);
      if (!snapshot) {
        throw new Error(
          `api-version "${chosenVersion}" is not defined in TypeSpec namespace ${rawNamespaceName}. Available TypeSpec versions: ${availableApiVersions.join(", ")}`,
        );
      }
      selectedApiVersion = chosenVersion;
      const mutated = unsafe_mutateSubgraphWithNamespace(
        program,
        [snapshot.mutator],
        serviceNamespace,
      );
      projectedNamespace = mutated.type as Namespace;
    } else if (versioningMutators?.kind === "transient") {
      const mutated = unsafe_mutateSubgraphWithNamespace(
        program,
        [versioningMutators.mutator],
        serviceNamespace,
      );
      projectedNamespace = mutated.type as Namespace;
      selectedApiVersion = requestedApiVersion ?? "unversioned";
      availableApiVersions = [selectedApiVersion];
    } else {
      selectedApiVersion = requestedApiVersion ?? "unversioned";
      availableApiVersions = [selectedApiVersion];
    }

    const tcgcContext = createTCGCContext(program, "@azure-tools/typespec-client-generator-core", {
      mutateNamespace: false,
    });
    const [httpOperations] = listHttpOperationsIn(program, projectedNamespace);
    const operationsById = new Map<string, HttpOperation>();
    const routeProviderCounts = new Map<string, number>();
    for (const httpOp of httpOperations) {
      const opId = resolveCanonicalOperationId(tcgcContext, program, httpOp.operation);
      operationsById.set(opId, httpOp);
      const providerMatches = [...httpOp.path.matchAll(/\/providers\/([^/?]+)/gi)].map((m) => m[1]);
      const targetRp = providerMatches[providerMatches.length - 1];
      if (
        targetRp &&
        !targetRp.startsWith("{") &&
        targetRp.toLowerCase() !== "microsoft.resources"
      ) {
        routeProviderCounts.set(targetRp, (routeProviderCounts.get(targetRp) ?? 0) + 1);
      }
    }

    const armDecoratorProvider =
      getArmProviderNamespace(program, projectedNamespace) ??
      getArmProviderNamespace(program, serviceNamespace);
    const majorityRouteProvider = [...routeProviderCounts.entries()].sort(
      (a, b) => b[1] - a[1],
    )[0]?.[0];
    const providerNamespace = armDecoratorProvider || majorityRouteProvider || rawNamespaceName;

    return {
      typespecProjectDir,
      entrypointFile,
      program,
      tcgcContext,
      serviceNamespace,
      projectedNamespace,
      providerNamespace,
      apiVersion: selectedApiVersion,
      availableApiVersions,
      httpOperations,
      operationsById,
    };
  })();

  loadedServiceCache.set(cacheKey, loadPromise);
  return loadPromise;
}
