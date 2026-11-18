import { getUnionAsEnum } from "@azure-tools/typespec-azure-core";
import {
  getDiscriminatedUnion,
  getDiscriminatedUnionFromInheritance,
  getDiscriminator,
  getMaxItems,
  getMaxLength,
  getMaxValue,
  getMinItems,
  getMinLength,
  getMinValue,
  getPattern,
  isArrayModelType,
  isNullType,
  isRecordModelType,
  isUnknownType,
  isVoidType,
  resolveEncodedName,
  walkPropertiesInherited,
  type Enum,
  type Model,
  type Program,
  type Scalar,
  type Tuple,
  type Type,
  type Union,
} from "@typespec/compiler";
import {
  createMetadataInfo,
  getPatchOptions,
  resolveRequestVisibility,
  Visibility,
  type HttpOperationResponse,
  type MetadataInfo,
} from "@typespec/http";
import { resolveBodyParameterName, type LoadedTypeSpecService } from "./typespec-loader.ts";
import type { TypeSpecSchemaIssue, WireHttpExchange } from "./types.ts";

interface ValidationContext {
  program: Program;
  metadataInfo: MetadataInfo;
  visibility: Visibility;
  isPatchImplicitOptional: boolean;
  strictEnumCase: boolean;
  issues: TypeSpecSchemaIssue[];
  activePairs: Set<string>;
}

function getRootScalarName(scalar: Scalar): string {
  let current: Scalar | undefined = scalar;
  while (current?.baseScalar) {
    current = current.baseScalar;
  }
  return current?.name ?? scalar.name;
}

function findScalarConstraint<T>(
  program: Program,
  scalar: Scalar,
  getter: (p: Program, t: Type) => T | undefined,
): T | undefined {
  let current: Scalar | undefined = scalar;
  while (current) {
    const val = getter(program, current);
    if (val !== undefined) {
      return val;
    }
    current = current.baseScalar;
  }
  return undefined;
}

const NUMERIC_SCALARS = new Set([
  "numeric",
  "integer",
  "float",
  "int8",
  "int16",
  "int32",
  "int64",
  "safeint",
  "uint8",
  "uint16",
  "uint32",
  "uint64",
  "float32",
  "float64",
  "decimal",
  "decimal128",
]);

const INTEGER_SCALARS = new Set([
  "integer",
  "int8",
  "int16",
  "int32",
  "int64",
  "safeint",
  "uint8",
  "uint16",
  "uint32",
  "uint64",
]);

function validateScalarValue(
  value: unknown,
  scalar: Scalar,
  jsonPath: string,
  ctx: ValidationContext,
): void {
  const rootName = getRootScalarName(scalar);

  if (
    rootName === "string" ||
    rootName === "url" ||
    rootName === "utcDateTime" ||
    rootName === "offsetDateTime" ||
    rootName === "plainDate" ||
    rootName === "plainTime" ||
    rootName === "duration" ||
    rootName === "bytes"
  ) {
    if (typeof value !== "string") {
      ctx.issues.push({
        code: "INVALID_SCALAR_TYPE",
        message: `Expected string (TypeSpec scalar "${scalar.name}") at ${jsonPath}, got ${typeof value}.`,
        path: jsonPath,
        severity: "error",
      });
      return;
    }
    const minLen =
      getMinLength(ctx.program, scalar) ?? findScalarConstraint(ctx.program, scalar, getMinLength);
    if (minLen !== undefined && value.length < minLen) {
      ctx.issues.push({
        code: "MIN_LENGTH_VIOLATION",
        message: `String length ${value.length} is less than @minLength(${minLen}) at ${jsonPath}.`,
        path: jsonPath,
        severity: "error",
      });
    }
    const maxLen =
      getMaxLength(ctx.program, scalar) ?? findScalarConstraint(ctx.program, scalar, getMaxLength);
    if (maxLen !== undefined && value.length > maxLen) {
      ctx.issues.push({
        code: "MAX_LENGTH_VIOLATION",
        message: `String length ${value.length} exceeds @maxLength(${maxLen}) at ${jsonPath}.`,
        path: jsonPath,
        severity: "error",
      });
    }
    const pattern =
      getPattern(ctx.program, scalar) ?? findScalarConstraint(ctx.program, scalar, getPattern);
    if (pattern) {
      try {
        const re = new RegExp(pattern);
        if (!re.test(value)) {
          ctx.issues.push({
            code: "PATTERN_VIOLATION",
            message: `Value "${value.slice(0, 60)}" does not match @pattern("${pattern}") at ${jsonPath}.`,
            path: jsonPath,
            severity: "warning",
          });
        }
      } catch {
        // Ignore non-JS regex dialects.
      }
    }
    return;
  }

  if (NUMERIC_SCALARS.has(rootName) || NUMERIC_SCALARS.has(scalar.name)) {
    if (typeof value !== "number" || !Number.isFinite(value)) {
      ctx.issues.push({
        code: "INVALID_SCALAR_TYPE",
        message: `Expected number (TypeSpec scalar "${scalar.name}") at ${jsonPath}, got ${typeof value}.`,
        path: jsonPath,
        severity: "error",
      });
      return;
    }
    if (
      (INTEGER_SCALARS.has(rootName) || INTEGER_SCALARS.has(scalar.name)) &&
      !Number.isInteger(value)
    ) {
      ctx.issues.push({
        code: "INVALID_INTEGER",
        message: `Expected integer (TypeSpec scalar "${scalar.name}") at ${jsonPath}, got ${value}.`,
        path: jsonPath,
        severity: "error",
      });
    }
    const minVal =
      getMinValue(ctx.program, scalar) ?? findScalarConstraint(ctx.program, scalar, getMinValue);
    if (minVal !== undefined && value < minVal) {
      ctx.issues.push({
        code: "MIN_VALUE_VIOLATION",
        message: `Value ${value} is less than @minValue(${minVal}) at ${jsonPath}.`,
        path: jsonPath,
        severity: "error",
      });
    }
    const maxVal =
      getMaxValue(ctx.program, scalar) ?? findScalarConstraint(ctx.program, scalar, getMaxValue);
    if (maxVal !== undefined && value > maxVal) {
      ctx.issues.push({
        code: "MAX_VALUE_VIOLATION",
        message: `Value ${value} exceeds @maxValue(${maxVal}) at ${jsonPath}.`,
        path: jsonPath,
        severity: "error",
      });
    }
    return;
  }

  if (rootName === "boolean") {
    if (typeof value !== "boolean") {
      ctx.issues.push({
        code: "INVALID_SCALAR_TYPE",
        message: `Expected boolean at ${jsonPath}, got ${typeof value}.`,
        path: jsonPath,
        severity: "error",
      });
    }
  }
}

function validateEnumValue(
  value: unknown,
  enumType: Enum,
  jsonPath: string,
  ctx: ValidationContext,
): void {
  const allowed = [...enumType.members.values()].map((m) => m.value ?? m.name);
  if (!allowed.includes(value as string | number)) {
    ctx.issues.push({
      code: "INVALID_ENUM_VALUE",
      message: `Value ${JSON.stringify(value)} is not a valid member of closed enum "${enumType.name}" ([${allowed.join(", ")}]) at ${jsonPath}.`,
      path: jsonPath,
      severity: "error",
    });
  }
}

function validateUnionValue(
  value: unknown,
  unionType: Union,
  jsonPath: string,
  ctx: ValidationContext,
): void {
  const variants = [...unionType.variants.values()];
  const allowsNull = variants.some((v) => isNullType(v.type));
  if (value === null) {
    if (!allowsNull) {
      ctx.issues.push({
        code: "UNEXPECTED_NULL",
        message: `Null is not permitted at ${jsonPath}.`,
        path: jsonPath,
        severity: "warning",
      });
    }
    return;
  }

  const nonNullVariants = variants.filter((v) => !isNullType(v.type));
  if (nonNullVariants.length === 1) {
    validateValueAgainstType(value, nonNullVariants[0].type, jsonPath, ctx);
    return;
  }

  const [unionEnum] = getUnionAsEnum(unionType);
  if (unionEnum) {
    const memberValues = [...unionEnum.flattenedMembers.values()].map((m) => m.value);
    if (!unionEnum.nullable && value === null) {
      ctx.issues.push({
        code: "UNEXPECTED_NULL",
        message: `Null is not permitted at ${jsonPath}.`,
        path: jsonPath,
        severity: "warning",
      });
      return;
    }
    if (memberValues.includes(value as string | number)) {
      return;
    }
    if (!unionEnum.open) {
      ctx.issues.push({
        code: "INVALID_UNION_ENUM_VALUE",
        message: `Value ${JSON.stringify(value)} is not in closed union "${unionType.name ?? "union"}" ([${memberValues.join(", ")}]) at ${jsonPath}.`,
        path: jsonPath,
        severity: "error",
      });
      return;
    }
    // Open extensible union (e.g. `union Foo { string, Key: "Key" }`).
    if (typeof value === "string") {
      const caseInsensitiveMatch = memberValues.find(
        (m) => typeof m === "string" && m.toLowerCase() === value.toLowerCase() && m !== value,
      );
      if (caseInsensitiveMatch !== undefined) {
        ctx.issues.push({
          code: "UNION_CASE_MISMATCH",
          message: `Value "${value}" differs in casing from declared TypeSpec union variant "${String(caseInsensitiveMatch)}" at ${jsonPath}.`,
          path: jsonPath,
          severity: ctx.strictEnumCase ? "error" : "warning",
        });
      }
      return;
    }
  }

  // Discriminated union check.
  const [discUnion] = getDiscriminatedUnion(ctx.program, unionType);
  if (discUnion && value && typeof value === "object" && !Array.isArray(value)) {
    const discProp = discUnion.options.discriminatorPropertyName;
    const discVal = (value as Record<string, unknown>)[discProp];
    if (typeof discVal === "string") {
      const matchedModel = discUnion.variants.get(discVal);
      if (matchedModel) {
        validateValueAgainstType(value, matchedModel, jsonPath, ctx);
        return;
      }
    }
  }

  // Fallback general union: try each variant and accept if any succeeds with 0 errors.
  for (const variant of nonNullVariants) {
    const probeCtx: ValidationContext = {
      ...ctx,
      issues: [],
      activePairs: new Set(ctx.activePairs),
    };
    validateValueAgainstType(value, variant.type, jsonPath, probeCtx);
    const hasError = probeCtx.issues.some((i) => i.severity === "error");
    if (!hasError) {
      ctx.issues.push(...probeCtx.issues);
      return;
    }
  }

  ctx.issues.push({
    code: "UNION_NO_MATCH",
    message: `Value at ${jsonPath} did not match any variant of TypeSpec union "${unionType.name ?? "anonymous"}".`,
    path: jsonPath,
    severity: "error",
  });
}

function validateTupleValue(
  value: unknown,
  tuple: Tuple,
  jsonPath: string,
  ctx: ValidationContext,
): void {
  if (!Array.isArray(value)) {
    ctx.issues.push({
      code: "INVALID_TUPLE",
      message: `Expected array tuple at ${jsonPath}, got ${typeof value}.`,
      path: jsonPath,
      severity: "error",
    });
    return;
  }
  const len = Math.min(value.length, tuple.values.length);
  for (let i = 0; i < len; i++) {
    validateValueAgainstType(value[i], tuple.values[i], `${jsonPath}[${i}]`, ctx);
  }
}

function validateModelValue(
  value: unknown,
  model: Model,
  jsonPath: string,
  ctx: ValidationContext,
): void {
  if (isArrayModelType(ctx.program, model)) {
    if (!Array.isArray(value)) {
      ctx.issues.push({
        code: "INVALID_ARRAY_TYPE",
        message: `Expected JSON array at ${jsonPath}, got ${value === null ? "null" : typeof value}.`,
        path: jsonPath,
        severity: "error",
      });
      return;
    }
    const minItems = getMinItems(ctx.program, model);
    if (minItems !== undefined && value.length < minItems) {
      ctx.issues.push({
        code: "MIN_ITEMS_VIOLATION",
        message: `Array length ${value.length} is less than @minItems(${minItems}) at ${jsonPath}.`,
        path: jsonPath,
        severity: "error",
      });
    }
    const maxItems = getMaxItems(ctx.program, model);
    if (maxItems !== undefined && value.length > maxItems) {
      ctx.issues.push({
        code: "MAX_ITEMS_VIOLATION",
        message: `Array length ${value.length} exceeds @maxItems(${maxItems}) at ${jsonPath}.`,
        path: jsonPath,
        severity: "error",
      });
    }
    const itemCtx: ValidationContext = {
      ...ctx,
      visibility: ctx.visibility | Visibility.Item,
    };
    for (let i = 0; i < value.length; i++) {
      validateValueAgainstType(value[i], model.indexer.value, `${jsonPath}[${i}]`, itemCtx);
    }
    return;
  }

  if (isRecordModelType(ctx.program, model)) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
      ctx.issues.push({
        code: "INVALID_OBJECT_TYPE",
        message: `Expected JSON object record at ${jsonPath}, got ${value === null ? "null" : Array.isArray(value) ? "array" : typeof value}.`,
        path: jsonPath,
        severity: "error",
      });
      return;
    }
    const itemCtx: ValidationContext = {
      ...ctx,
      visibility: ctx.visibility | Visibility.Item,
    };
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (v !== null && v !== undefined) {
        validateValueAgainstType(v, model.indexer.value, `${jsonPath}.${k}`, itemCtx);
      }
    }
    return;
  }

  if (!value || typeof value !== "object" || Array.isArray(value)) {
    ctx.issues.push({
      code: "INVALID_OBJECT_TYPE",
      message: `Expected JSON object (TypeSpec model "${model.name || "object"}") at ${jsonPath}, got ${value === null ? "null" : Array.isArray(value) ? "array" : typeof value}.`,
      path: jsonPath,
      severity: "error",
    });
    return;
  }

  let effectiveModel = model;
  const disc = getDiscriminator(ctx.program, model);
  if (disc) {
    const [inhDisc] = getDiscriminatedUnionFromInheritance(model, disc);
    const discVal = (value as Record<string, unknown>)[inhDisc.propertyName];
    if (typeof discVal === "string") {
      const derived = inhDisc.variants.get(discVal);
      if (derived) {
        effectiveModel = derived;
      }
    }
  }

  const obj = value as Record<string, unknown>;
  const knownWireProps = new Set<string>();

  for (const prop of walkPropertiesInherited(effectiveModel)) {
    if (!ctx.metadataInfo.isPayloadProperty(prop, ctx.visibility)) {
      continue;
    }
    const wireName = resolveEncodedName(ctx.program, prop, "application/json");
    knownWireProps.add(wireName);

    const isOptional =
      ctx.isPatchImplicitOptional ||
      prop.optional ||
      ctx.metadataInfo.isOptional(prop, ctx.visibility);
    const propVal = obj[wireName];

    if (propVal === undefined) {
      if (!isOptional) {
        ctx.issues.push({
          code: "MISSING_REQUIRED_PROPERTY",
          message: `Missing required property "${wireName}" on model "${effectiveModel.name || "object"}" at ${jsonPath}.${wireName}.`,
          path: `${jsonPath}.${wireName}`,
          severity: "error",
        });
      }
      continue;
    }

    if (propVal === null) {
      // ARM services commonly serialize unset optional complex/string fields as null on wire.
      if (prop.type.kind === "Union") {
        validateUnionValue(propVal, prop.type, `${jsonPath}.${wireName}`, ctx);
      } else if (!isOptional) {
        ctx.issues.push({
          code: "NULL_REQUIRED_PROPERTY",
          message: `Required property "${wireName}" is null at ${jsonPath}.${wireName}.`,
          path: `${jsonPath}.${wireName}`,
          severity: "error",
        });
      }
      continue;
    }

    // Check property-level string/array constraints before recursing into prop.type.
    if (typeof propVal === "string") {
      const pMinLen = getMinLength(ctx.program, prop);
      if (pMinLen !== undefined && propVal.length < pMinLen) {
        ctx.issues.push({
          code: "MIN_LENGTH_VIOLATION",
          message: `Property "${wireName}" length ${propVal.length} is less than @minLength(${pMinLen}) at ${jsonPath}.${wireName}.`,
          path: `${jsonPath}.${wireName}`,
          severity: "error",
        });
      }
      const pMaxLen = getMaxLength(ctx.program, prop);
      if (pMaxLen !== undefined && propVal.length > pMaxLen) {
        ctx.issues.push({
          code: "MAX_LENGTH_VIOLATION",
          message: `Property "${wireName}" length ${propVal.length} exceeds @maxLength(${pMaxLen}) at ${jsonPath}.${wireName}.`,
          path: `${jsonPath}.${wireName}`,
          severity: "error",
        });
      }
    } else if (Array.isArray(propVal)) {
      const pMinItems = getMinItems(ctx.program, prop);
      if (pMinItems !== undefined && propVal.length < pMinItems) {
        ctx.issues.push({
          code: "MIN_ITEMS_VIOLATION",
          message: `Property "${wireName}" length ${propVal.length} is less than @minItems(${pMinItems}) at ${jsonPath}.${wireName}.`,
          path: `${jsonPath}.${wireName}`,
          severity: "error",
        });
      }
      const pMaxItems = getMaxItems(ctx.program, prop);
      if (pMaxItems !== undefined && propVal.length > pMaxItems) {
        ctx.issues.push({
          code: "MAX_ITEMS_VIOLATION",
          message: `Property "${wireName}" length ${propVal.length} exceeds @maxItems(${pMaxItems}) at ${jsonPath}.${wireName}.`,
          path: `${jsonPath}.${wireName}`,
          severity: "error",
        });
      }
    }

    validateValueAgainstType(propVal, prop.type, `${jsonPath}.${wireName}`, ctx);
  }

  if (effectiveModel.indexer) {
    const itemCtx: ValidationContext = {
      ...ctx,
      visibility: ctx.visibility | Visibility.Item,
    };
    for (const [k, v] of Object.entries(obj)) {
      if (!knownWireProps.has(k) && v !== undefined && v !== null) {
        validateValueAgainstType(v, effectiveModel.indexer.value, `${jsonPath}.${k}`, itemCtx);
      }
    }
  }
}

export function validateValueAgainstType(
  value: unknown,
  type: Type,
  jsonPath: string,
  ctx: ValidationContext,
): void {
  if (isUnknownType(type) || isVoidType(type)) {
    return;
  }

  if (type.kind === "Intrinsic") {
    if (isNullType(type) && value !== null) {
      ctx.issues.push({
        code: "EXPECTED_NULL",
        message: `Expected null at ${jsonPath}, got ${typeof value}.`,
        path: jsonPath,
        severity: "error",
      });
    }
    return;
  }

  if (type.kind === "String") {
    if (value !== type.value) {
      ctx.issues.push({
        code: "LITERAL_MISMATCH",
        message: `Expected string literal "${type.value}" at ${jsonPath}, got ${JSON.stringify(value)}.`,
        path: jsonPath,
        severity: "error",
      });
    }
    return;
  }

  if (type.kind === "Number") {
    if (value !== type.value) {
      ctx.issues.push({
        code: "LITERAL_MISMATCH",
        message: `Expected numeric literal ${type.value} at ${jsonPath}, got ${JSON.stringify(value)}.`,
        path: jsonPath,
        severity: "error",
      });
    }
    return;
  }

  if (type.kind === "Boolean") {
    if (value !== type.value) {
      ctx.issues.push({
        code: "LITERAL_MISMATCH",
        message: `Expected boolean literal ${String(type.value)} at ${jsonPath}, got ${JSON.stringify(value)}.`,
        path: jsonPath,
        severity: "error",
      });
    }
    return;
  }

  if (type.kind === "Scalar") {
    validateScalarValue(value, type, jsonPath, ctx);
    return;
  }

  if (type.kind === "Enum") {
    validateEnumValue(value, type, jsonPath, ctx);
    return;
  }

  if (type.kind === "Union") {
    validateUnionValue(value, type, jsonPath, ctx);
    return;
  }

  if (type.kind === "Tuple") {
    validateTupleValue(value, type, jsonPath, ctx);
    return;
  }

  if (type.kind === "Model") {
    const cycleKey = `${jsonPath}::${type.name || "anon"}`;
    if (ctx.activePairs.has(cycleKey)) {
      return;
    }
    ctx.activePairs.add(cycleKey);
    validateModelValue(value, type, jsonPath, ctx);
    ctx.activePairs.delete(cycleKey);
  }
}

function matchHttpResponseForStatus(
  responses: HttpOperationResponse[],
  statusCode: number,
): HttpOperationResponse | undefined {
  for (const r of responses) {
    if (r.statusCodes === statusCode) {
      return r;
    }
  }
  for (const r of responses) {
    if (
      typeof r.statusCodes === "object" &&
      statusCode >= r.statusCodes.start &&
      statusCode <= r.statusCodes.end
    ) {
      return r;
    }
  }
  if (statusCode >= 400) {
    return responses.find((r) => r.statusCodes === "*");
  }
  return undefined;
}

export function validateWireExchangeAgainstTypeSpec(
  service: LoadedTypeSpecService,
  operationId: string,
  exchange: WireHttpExchange,
): {
  requestErrors: TypeSpecSchemaIssue[];
  responseErrors: TypeSpecSchemaIssue[];
} {
  const httpOp = service.operationsById.get(operationId);
  if (!httpOp) {
    return {
      requestErrors: [],
      responseErrors: [
        {
          code: "UNKNOWN_OPERATION",
          message: `Operation "${operationId}" not found in projected TypeSpec service.`,
          path: "$",
          severity: "error",
        },
      ],
    };
  }

  const metadataInfo = createMetadataInfo(service.program);
  const reqVisibility = resolveRequestVisibility(service.program, httpOp.operation, httpOp.verb);
  const patchOpts =
    httpOp.verb === "patch" ? getPatchOptions(service.program, httpOp.operation) : undefined;
  const isPatchImplicitOptional =
    httpOp.verb === "patch" && patchOpts?.implicitOptionality !== false;

  const reqCtx: ValidationContext = {
    program: service.program,
    metadataInfo,
    visibility: reqVisibility,
    isPatchImplicitOptional,
    strictEnumCase: false,
    issues: [],
    activePairs: new Set(),
  };

  // Validate query & header parameters on initial step only.
  if (exchange.step === "initial") {
    const parsedUrl = new URL(exchange.request.url);
    for (const p of httpOp.parameters.parameters) {
      if (p.type === "query") {
        const val = parsedUrl.searchParams.get(p.name);
        if (val === null && !p.param.optional) {
          reqCtx.issues.push({
            code: "MISSING_REQUIRED_QUERY_PARAM",
            message: `Missing required query parameter "${p.name}".`,
            path: `$.query.${p.name}`,
            severity: "error",
          });
        }
      } else if (p.type === "header" && p.name.toLowerCase() !== "content-type") {
        const val =
          exchange.request.headers[p.name] ?? exchange.request.headers[p.name.toLowerCase()];
        if (val === undefined && !p.param.optional) {
          reqCtx.issues.push({
            code: "MISSING_REQUIRED_HEADER_PARAM",
            message: `Missing required request header "${p.name}".`,
            path: `$.headers.${p.name}`,
            severity: "error",
          });
        }
      }
    }

    const reqBody = httpOp.parameters.body;
    if (reqBody && !isVoidType(reqBody.type)) {
      const bodyOptional = reqBody.property ? reqBody.property.optional : false;
      if (exchange.request.body === undefined) {
        if (!bodyOptional) {
          reqCtx.issues.push({
            code: "MISSING_REQUIRED_BODY",
            message: `Missing required request body on ${operationId}.`,
            path: "$.body",
            severity: "error",
          });
        }
      } else {
        validateValueAgainstType(exchange.request.body, reqBody.type, "$.body", reqCtx);
      }
    }
  }

  const respCtx: ValidationContext = {
    program: service.program,
    metadataInfo,
    visibility: Visibility.Read,
    isPatchImplicitOptional: false,
    strictEnumCase: false,
    issues: [],
    activePairs: new Set(),
  };

  // For final-get on PUT/PATCH, find the matching GET operation on the same route if available, else validate against 200 response of httpOp.
  let targetRespOp = httpOp;
  if (exchange.step === "final-get" && exchange.request.method === "GET" && httpOp.verb !== "get") {
    const siblingGet = service.httpOperations.find(
      (candidate) => candidate.verb === "get" && candidate.path === httpOp.path,
    );
    if (siblingGet) {
      targetRespOp = siblingGet;
    }
  }

  const matchedResp = matchHttpResponseForStatus(targetRespOp.responses, exchange.response.status);
  if (matchedResp) {
    const respBody = matchedResp.responses.find((c) => c.body !== undefined)?.body;
    if (respBody && !isVoidType(respBody.type) && exchange.response.body !== undefined) {
      validateValueAgainstType(exchange.response.body, respBody.type, "$.response.body", respCtx);
    }
  }

  return {
    requestErrors: reqCtx.issues,
    responseErrors: respCtx.issues,
  };
}

export interface TypeSpecExampleDocument {
  title?: string;
  operationId?: string;
  parameters?: Record<string, unknown>;
  responses?: Record<
    string,
    {
      headers?: Record<string, string>;
      body?: unknown;
    }
  >;
}

export function validateExampleAgainstTypeSpec(
  service: LoadedTypeSpecService,
  operationId: string,
  exampleDoc: TypeSpecExampleDocument,
): TypeSpecSchemaIssue[] {
  const issues: TypeSpecSchemaIssue[] = [];
  const httpOp = service.operationsById.get(operationId);
  if (!httpOp) {
    issues.push({
      code: "UNKNOWN_OPERATION",
      message: `Operation "${operationId}" does not exist in TypeSpec for version ${service.apiVersion}.`,
      path: "$.operationId",
      severity: "error",
    });
    return issues;
  }

  const metadataInfo = createMetadataInfo(service.program);
  const reqVisibility = resolveRequestVisibility(service.program, httpOp.operation, httpOp.verb);
  const patchOpts =
    httpOp.verb === "patch" ? getPatchOptions(service.program, httpOp.operation) : undefined;
  const isPatchImplicitOptional =
    httpOp.verb === "patch" && patchOpts?.implicitOptionality !== false;

  const params = exampleDoc.parameters ?? {};

  for (const p of httpOp.parameters.parameters) {
    if (p.type === "header" && p.name.toLowerCase() === "content-type") {
      continue;
    }
    const wireParamName = p.name;
    const val = params[wireParamName] ?? params[p.param.name];
    if (val === undefined && !p.param.optional) {
      issues.push({
        code: "MISSING_EXAMPLE_PARAMETER",
        message: `Example omits required ${p.type} parameter "${wireParamName}".`,
        path: `$.parameters.${wireParamName}`,
        severity: "error",
      });
    }
  }

  const reqBody = httpOp.parameters.body;
  if (reqBody && !isVoidType(reqBody.type)) {
    const bodyParamName = resolveBodyParameterName(service.tcgcContext, reqBody.property);
    const bodyVal = params[bodyParamName] ?? params.parameters ?? params.resource ?? params.body;
    const bodyOptional = reqBody.property ? reqBody.property.optional : false;
    if (bodyVal === undefined) {
      if (!bodyOptional) {
        issues.push({
          code: "MISSING_EXAMPLE_BODY",
          message: `Example omits required request body parameter "${bodyParamName}".`,
          path: `$.parameters.${bodyParamName}`,
          severity: "error",
        });
      }
    } else {
      const bodyCtx: ValidationContext = {
        program: service.program,
        metadataInfo,
        visibility: reqVisibility,
        isPatchImplicitOptional,
        strictEnumCase: true,
        issues,
        activePairs: new Set(),
      };
      validateValueAgainstType(bodyVal, reqBody.type, `$.parameters.${bodyParamName}`, bodyCtx);
    }
  }

  const responses = exampleDoc.responses ?? {};
  for (const [statusKey, respEntry] of Object.entries(responses)) {
    const statusNum = Number(statusKey);
    const matchedResp = Number.isFinite(statusNum)
      ? matchHttpResponseForStatus(httpOp.responses, statusNum)
      : undefined;
    if (!matchedResp || matchedResp.statusCodes === "*") {
      issues.push({
        code: "UNDOCUMENTED_EXAMPLE_STATUS",
        message: `Example response status "${statusKey}" is not declared on TypeSpec operation "${operationId}".`,
        path: `$.responses.${statusKey}`,
        severity: "error",
      });
      continue;
    }

    const declaredBody = matchedResp.responses.find((c) => c.body !== undefined)?.body;
    const hasDeclaredBody = Boolean(declaredBody && !isVoidType(declaredBody.type));
    if (!hasDeclaredBody && respEntry?.body !== undefined) {
      issues.push({
        code: "RESPONSE_SCHEMA_NOT_IN_TYPESPEC",
        message: `Response status "${statusKey}" on "${operationId}" includes a JSON body in the live example, but TypeSpec declares no response body for ${statusKey}.`,
        path: `$.responses.${statusKey}.body`,
        severity: "error",
      });
      continue;
    }

    if (hasDeclaredBody && declaredBody && respEntry?.body !== undefined) {
      const respCtx: ValidationContext = {
        program: service.program,
        metadataInfo,
        visibility: Visibility.Read,
        isPatchImplicitOptional: false,
        strictEnumCase: true,
        issues,
        activePairs: new Set(),
      };
      validateValueAgainstType(
        respEntry.body,
        declaredBody.type,
        `$.responses.${statusKey}.body`,
        respCtx,
      );
    }
  }

  return issues;
}
