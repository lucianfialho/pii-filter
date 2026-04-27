import { createHash } from "node:crypto";
import { PII_PATTERNS, PII_FIELD_NAMES } from "./patterns.js";

export type RedactOptions = { mode: "redact"; knownPiiFields?: string[] };
export type PseudonymizeOptions = { mode: "pseudonymize"; salt: string; knownPiiFields?: string[] };
export type FilterOptions = RedactOptions | PseudonymizeOptions;

/**
 * Scan an OpenAPI schema object and return dot-notation paths of PII fields.
 * Pass the result as `knownPiiFields` to filterPii() for faster, precise filtering.
 *
 * @example
 * const schema = { customer: { email: { type: "string", format: "email" }, age: { type: "integer" } } }
 * scanSchema(schema) // → ["customer.email"]
 */
export function scanSchema(schema: Record<string, unknown>, prefix = ""): string[] {
  const piiFields: string[] = [];

  for (const [key, value] of Object.entries(schema)) {
    const path = prefix ? `${prefix}.${key}` : key;

    if (key === "properties" && typeof value === "object" && value !== null) {
      piiFields.push(...scanSchema(value as Record<string, unknown>, prefix));
      continue;
    }

    if (typeof value === "object" && value !== null) {
      const prop = value as Record<string, unknown>;
      const isPiiByName = PII_FIELD_NAMES.has(key.toLowerCase());
      const isPiiByFormat = typeof prop.format === "string" &&
        ["email", "password", "phone", "uri"].includes(prop.format);
      const isPiiByDescription = typeof prop.description === "string" &&
        /\b(pii|personal|private|sensitive|confidential)\b/i.test(prop.description);

      if (isPiiByName || isPiiByFormat || isPiiByDescription) {
        piiFields.push(path);
      } else {
        piiFields.push(...scanSchema(prop, path));
      }
    }
  }

  return piiFields;
}

function hashValue(value: string, salt: string): string {
  return createHash("sha256").update(salt + value).digest("hex").slice(0, 16);
}

function replaceValue(value: string, options: FilterOptions): string {
  if (options.mode === "redact") return "[REDACTED]";
  return `[${hashValue(value, options.salt)}]`;
}

function filterString(text: string, options: FilterOptions): string {
  let result = text;
  for (const { type, regex } of PII_PATTERNS) {
    result = result.replace(regex, (match) =>
      options.mode === "redact" ? `[${type}]` : `[${hashValue(match, options.salt)}]`
    );
  }
  return result;
}

function filterValue(value: unknown, options: FilterOptions, currentPath: string): unknown {
  if (typeof value === "string") return filterString(value, options);
  if (Array.isArray(value)) return value.map((v) => filterValue(v, options, currentPath));
  if (value !== null && typeof value === "object") return filterObject(value as Record<string, unknown>, options, currentPath);
  return value;
}

function isKnownPiiPath(path: string, knownPiiFields: string[]): boolean {
  return knownPiiFields.some((f) => f === path || path.startsWith(f + "."));
}

function filterObject(
  obj: Record<string, unknown>,
  options: FilterOptions,
  parentPath = ""
): Record<string, unknown> {
  const knownPiiFields = options.knownPiiFields ?? [];
  const result: Record<string, unknown> = {};

  for (const [key, val] of Object.entries(obj)) {
    const path = parentPath ? `${parentPath}.${key}` : key;
    const isPiiByKnownField = isKnownPiiPath(path, knownPiiFields);
    const isPiiByName = PII_FIELD_NAMES.has(key.toLowerCase());

    if ((isPiiByKnownField || isPiiByName) && typeof val === "string") {
      result[key] = replaceValue(val, options);
    } else {
      result[key] = filterValue(val, options, path);
    }
  }

  return result;
}

/**
 * Filter PII from a string or JSON object.
 *
 * Optionally pass `knownPiiFields` (dot-notation paths from `scanSchema()`)
 * to skip regex scanning on fields already identified from the OpenAPI schema.
 *
 * @example
 * // With schema-derived field list (faster, more precise)
 * const piiFields = scanSchema(openApiSchema);
 * filterPii(response, { mode: "pseudonymize", salt: process.env.PII_SALT!, knownPiiFields: piiFields })
 *
 * @example
 * // Without schema (regex-only detection)
 * filterPii({ email: "user@example.com" }, { mode: "redact" })
 * // → { email: "[REDACTED]" }
 */
export function filterPii(input: string, options: FilterOptions): string;
export function filterPii(input: Record<string, unknown>, options: FilterOptions): Record<string, unknown>;
export function filterPii(input: unknown, options: FilterOptions): unknown {
  if (typeof input === "string") return filterString(input, options);
  if (input !== null && typeof input === "object") return filterObject(input as Record<string, unknown>, options);
  return input;
}

export { PII_PATTERNS, PII_FIELD_NAMES };
