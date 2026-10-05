/**
 * @module mcp/schema
 * @description A validator for the subset of JSON Schema that the tool
 * declarations use, so that tool arguments are checked against exactly the
 * schema that is advertised to clients.
 * @internal
 */

import type { JsonSchema } from "./definitions.js";

function typeOf(value: unknown): string {
  if (value === null) return "null";
  if (Array.isArray(value)) return "array";
  if (typeof value === "number") return Number.isInteger(value) ? "integer" : "number";
  return typeof value;
}

/**
 * Validate `value` against `schema`.
 *
 * @returns One message per violation, each prefixed with a JSON Pointer; empty when valid.
 * @internal
 */
export function validate(schema: JsonSchema, value: unknown, path = ""): string[] {
  const errors: string[] = [];
  const at = path === "" ? "/" : path;
  const actual = typeOf(value);

  if (
    schema.type !== undefined &&
    actual !== schema.type &&
    !(schema.type === "number" && actual === "integer")
  ) {
    return [`${at}: expected ${schema.type}, got ${actual}`];
  }
  if (schema.enum !== undefined && !(typeof value === "string" && schema.enum.includes(value))) {
    errors.push(`${at}: must be one of ${schema.enum.join(", ")}`);
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      errors.push(`${at}: must have at least ${String(schema.minLength)} characters`);
    }
    if (schema.maxLength !== undefined && value.length > schema.maxLength) {
      errors.push(`${at}: must have at most ${String(schema.maxLength)} characters`);
    }
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) {
      errors.push(`${at}: must be at least ${String(schema.minimum)}`);
    }
    if (schema.maximum !== undefined && value > schema.maximum) {
      errors.push(`${at}: must be at most ${String(schema.maximum)}`);
    }
  }
  if (Array.isArray(value)) {
    if (schema.minItems !== undefined && value.length < schema.minItems) {
      errors.push(`${at}: must have at least ${String(schema.minItems)} item(s)`);
    }
    if (schema.maxItems !== undefined && value.length > schema.maxItems) {
      // The items of an oversized array are not looked at: one message, not one per item.
      return [...errors, `${at}: must have at most ${String(schema.maxItems)} items`];
    }
    if (schema.items !== undefined) {
      for (const [index, item] of (value as unknown[]).entries()) {
        errors.push(...validate(schema.items, item, `${path}/${String(index)}`));
      }
    }
  }
  if (actual === "object" && schema.type === "object") {
    const record = value as Record<string, unknown>;
    const properties = schema.properties ?? {};
    for (const name of schema.required ?? []) {
      if (!Object.hasOwn(record, name)) errors.push(`${path}/${name}: is required`);
    }
    for (const [name, member] of Object.entries(record)) {
      const propertySchema = Object.hasOwn(properties, name) ? properties[name] : undefined;
      if (propertySchema !== undefined) {
        errors.push(...validate(propertySchema, member, `${path}/${name}`));
      } else if (schema.additionalProperties === false) {
        errors.push(`${path}/${name}: is not a known parameter`);
      }
    }
  }
  return errors;
}
