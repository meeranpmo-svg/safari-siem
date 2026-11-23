// Copyright (c) 2026 Citynet Work and Zyberon Information Technology, Saudi Arabia. All rights reserved. Proprietary and confidential - see LICENSE.
'use strict';
/* ai-schema.js - the same file as the SIEM's engine/util/ai-schema.js (a test keeps the two identical).
 * A model's tool call is checked against the tool's declared input_schema BEFORE the tool runs (CLAUDE.md, AI features:
 * "schema-checked inputs"). The model's arguments are untrusted: a field the tool did not declare, a wrong type, a missing required
 * field, a value outside its range, length, pattern or list is refused with a message naming the field, and the tool is not run.
 *
 * Fail closed:
 *   - an object takes only the properties it declares (additionalProperties left out is read as false)
 *   - a string without maxLength is capped at 20000 characters, an array without maxItems at 500 items
 *   - schemaProblem() refuses a schema that uses anything this checker does not understand, so a tool is never registered with a
 *     rule that would silently not be enforced (intel-kit.js calls it when an advisor is created)
 * Supported: type object / string / integer / number / boolean / array; properties, required, additionalProperties (false only),
 * minimum, maximum, minLength, maxLength, pattern, enum, items, minItems, maxItems; description and default are notes.
 * assertSchemas(tools, where) throws when a tool's schema uses a rule this checker cannot enforce - call it where the tools are built.
 */
const TYPES = ['object', 'string', 'integer', 'number', 'boolean', 'array'];
const KEYS = new Set(['type', 'properties', 'required', 'additionalProperties', 'minimum', 'maximum', 'minLength', 'maxLength', 'pattern', 'enum', 'items', 'minItems', 'maxItems', 'description', 'default']);
const STR_MAX = 20000, ARR_MAX = 500;   // the size a tool result may have; a long report through a final tool fits

// null when this checker can enforce every rule in the schema, else what it cannot
function schemaProblem(s, at = 'input_schema') {
  if (!s || typeof s !== 'object' || Array.isArray(s)) return at + ' is not a schema';
  for (const k of Object.keys(s)) if (!KEYS.has(k)) return at + '.' + k + ' is not supported';
  if (!TYPES.includes(s.type)) return at + '.type ' + JSON.stringify(s.type) + ' is not supported';
  if (s.additionalProperties !== undefined && s.additionalProperties !== false) return at + '.additionalProperties: only false is supported';
  if (s.required !== undefined && (!Array.isArray(s.required) || s.required.some((r) => !(s.properties || {})[r]))) return at + '.required names a property that is not declared';
  if (s.enum !== undefined && !Array.isArray(s.enum)) return at + '.enum must be a list';
  if (s.pattern !== undefined) { try { new RegExp(s.pattern); } catch (e) { return at + '.pattern is not a valid pattern'; } }
  if (s.type === 'object') for (const [k, p] of Object.entries(s.properties || {})) { const e = schemaProblem(p, at + '.properties.' + k); if (e) return e; }
  if (s.type === 'array') { if (!s.items) return at + '.items is required for an array'; const e = schemaProblem(s.items, at + '.items'); if (e) return e; }
  return null;
}

const show = (v) => { const t = JSON.stringify(v); return t && t.length > 40 ? t.slice(0, 40) + '…' : t; };
// null when the value fits the schema, else a message naming the field
function checkInput(s, v, at = 'input') {
  const inEnum = () => (s.enum && !s.enum.some((x) => x === v) ? at + ' must be one of ' + s.enum.map(show).join(', ') : null);
  const range = () => (s.minimum !== undefined && v < s.minimum ? at + ' must be at least ' + s.minimum : s.maximum !== undefined && v > s.maximum ? at + ' must be at most ' + s.maximum : null);
  switch (s.type) {
    case 'object': {
      if (!v || typeof v !== 'object' || Array.isArray(v)) return at + ' must be an object';
      const P = s.properties || {};
      for (const r of s.required || []) if (v[r] === undefined || v[r] === null) return at + '.' + r + ' is required';
      for (const k of Object.keys(v)) { if (!Object.prototype.hasOwnProperty.call(P, k)) return at + '.' + k + ' is not allowed'; if (v[k] === undefined) continue; const e = checkInput(P[k], v[k], at + '.' + k); if (e) return e; }
      return null;
    }
    case 'string':
      if (typeof v !== 'string') return at + ' must be text';
      if (v.length > (s.maxLength !== undefined ? s.maxLength : STR_MAX)) return at + ' is longer than ' + (s.maxLength !== undefined ? s.maxLength : STR_MAX) + ' characters';
      if (s.minLength !== undefined && v.length < s.minLength) return at + ' must be at least ' + s.minLength + ' characters';
      if (s.pattern !== undefined && !new RegExp(s.pattern).test(v)) return at + ' has an invalid format';
      return inEnum();
    case 'integer': if (!Number.isInteger(v)) return at + ' must be a whole number'; return range() || inEnum();
    case 'number': if (typeof v !== 'number' || !Number.isFinite(v)) return at + ' must be a number'; return range() || inEnum();
    case 'boolean': return typeof v === 'boolean' ? null : at + ' must be true or false';
    case 'array': {
      if (!Array.isArray(v)) return at + ' must be a list';
      const max = s.maxItems !== undefined ? s.maxItems : ARR_MAX;
      if (v.length > max) return at + ' has more than ' + max + ' items';
      if (s.minItems !== undefined && v.length < s.minItems) return at + ' needs at least ' + s.minItems + ' items';
      for (let i = 0; i < v.length; i++) { const e = checkInput(s.items, v[i], at + '[' + i + ']'); if (e) return e; }
      return null;
    }
    default: return at + ' has a type this platform does not check';   // schemaProblem() keeps such a schema out; fail closed anyway
  }
}

function assertSchemas(tools, where) {
  for (const t of tools || []) { const e = schemaProblem(t.input_schema); if (e) throw new Error((where || 'AI tools') + ': tool ' + t.name + ': ' + e); }
  return tools;
}

module.exports = { checkInput, schemaProblem, assertSchemas, STR_MAX, ARR_MAX };
