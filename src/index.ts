import { createHash } from "node:crypto";
import { PII_PATTERNS, PII_FIELD_NAMES } from "./patterns.js";

export type RedactOptions = { mode: "redact" };
export type PseudonymizeOptions = { mode: "pseudonymize"; salt: string };
export type FilterOptions = RedactOptions | PseudonymizeOptions;

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

function filterValue(value: unknown, options: FilterOptions): unknown {
  if (typeof value === "string") return filterString(value, options);
  if (Array.isArray(value)) return value.map((v) => filterValue(v, options));
  if (value !== null && typeof value === "object") return filterObject(value as Record<string, unknown>, options);
  return value;
}

function filterObject(obj: Record<string, unknown>, options: FilterOptions): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(obj)) {
    const isPiiField = PII_FIELD_NAMES.has(key.toLowerCase());
    if (isPiiField && typeof val === "string") {
      result[key] = replaceValue(val, options);
    } else {
      result[key] = filterValue(val, options);
    }
  }
  return result;
}

/**
 * Filter PII from a string or JSON object.
 *
 * @example
 * // Redact — removes PII irreversibly
 * filterPii({ email: "user@example.com" }, { mode: "redact" })
 * // → { email: "[REDACTED]" }
 *
 * @example
 * // Pseudonymize — deterministic SHA256+salt (GDPR-compliant with secret salt)
 * filterPii({ email: "user@example.com" }, { mode: "pseudonymize", salt: process.env.PII_SALT! })
 * // → { email: "[a3f8c2d1e4b5f6a7]" }
 */
export function filterPii(input: string, options: FilterOptions): string;
export function filterPii(input: Record<string, unknown>, options: FilterOptions): Record<string, unknown>;
export function filterPii(input: unknown, options: FilterOptions): unknown {
  if (typeof input === "string") return filterString(input, options);
  if (input !== null && typeof input === "object") return filterObject(input as Record<string, unknown>, options);
  return input;
}

export { PII_PATTERNS, PII_FIELD_NAMES };
