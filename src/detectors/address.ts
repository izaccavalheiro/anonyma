/**
 * @module detectors/address
 * @description Heuristic detector for physical street addresses (US, UK, EU formats).
 *
 * Detection combines:
 * - Common address context keywords ("address:", "lives at", "ship to", etc.)
 * - US street patterns: number + direction + street name + type
 * - European and Brazilian street patterns: `Musterstraße 12`, `Kerkstraat 5`,
 *   `12 rue de la Paix`, `Calle Mayor 5`, `Via Roma 10`, `Av. Paulista, 1578`,
 *   with an optional postcode and town after them (`10115 Berlin`, `01310-100 São Paulo`)
 * - UK postcode patterns
 * - PO Box patterns
 *
 * Confidence: 0.80 (heuristic — high false-negative rate for uncommon formats).
 */

import type { PiiMatch } from "../types.js";

/**
 * US-style street address: optional apt/suite, followed by city+state+zip or just zip context.
 * Pattern: number + optional direction + words + street type
 * @internal
 */
const US_STREET_PATTERN =
  /\b\d{1,5}\s+(?:(?:N|S|E|W|NE|NW|SE|SW|North|South|East|West|Northeast|Northwest|Southeast|Southwest)\.?\s+)?(?:[A-Z][a-z]+\s+){1,4}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Rd|Road|Ln|Lane|Ct|Court|Pl|Place|Cir|Circle|Way|Pkwy|Parkway|Hwy|Highway|Trl|Trail|Terr(?:ace)?|Terr)\.?(?:\s+(?:Apt|Apartment|Suite|Ste|Unit|#)\s*\w+)?\b/gi;

/**
 * Postcode and town that may follow a European or Brazilian street address:
 * `10115 Berlin`, `75002 Paris`, `1012 AB Amsterdam`, `1000-001 Lisboa`,
 * `01310-100 São Paulo`.
 * @internal
 */
const EU_TOWN = String.raw`(?:,?\s+(?:[A-Z]{1,2}-)?\d{4,5}(?:-\d{3}|\s[A-Z]{2})?\s+\p{Lu}[\p{L}'-]+(?:\s\p{Lu}[\p{L}'-]+)?)?`;

/** Street types that German, Dutch and the Scandinavian languages append to the name. @internal */
const STREET_SUFFIX = String.raw`(?:stra(?:ß|ss)e|str\.|weg|gasse|platz|allee|damm|ufer|straat|laan|gracht|plein|kade|singel|gatan|vägen|veien|gade)`;

/** The same street types written as a word of their own: `Berliner Straße`. @internal */
const STREET_WORD = String.raw`(?:Stra(?:ß|ss)e|Str\.|Weg|Gasse|Platz|Allee|Damm|Ufer|Straat|Laan)`;

/**
 * Street names that end in their street type, then the house number:
 * `Musterstraße 12`, `Berliner Str. 5a`, `Kerkstraat 12`, `Storgatan 3`.
 * @internal
 */
const SUFFIX_STREET_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\d])(?:\p{Lu}\p{Ll}*${STREET_SUFFIX}|\p{Lu}\p{Ll}+[\s-]${STREET_WORD})\s+\d{1,4}\s?[a-z]?(?![\p{L}\d])` +
    EU_TOWN,
  "gu",
);

/**
 * Street types written before the name, as French, Spanish, Catalan, Italian
 * and Portuguese write them.
 * @internal
 */
const STREET_TYPE = String.raw`(?:[Rr]ue|[Aa]venue|[Bb]oulevard|[Bb]d|[Cc]hemin|[Ii]mpasse|[Aa]llée|[Qq]uai|Calle|C\/|Avenida|Avda\.|Av\.|Paseo|Plaza|Carrer|Via|Viale|Piazza|Corso|Largo|Rua|Travessa|Praça|Alameda|Estrada|Rodovia)`;

/** Articles and prepositions inside a street name: `rue de la Paix`, `Rua das Flores`. @internal */
const NAME_LINK = String.raw`(?:(?:de|del|de la|des|du|d'|la|le|l'|las|los|el|da|das|do|dos|di|della|delle|dei)\s?)`;

/** A capitalised street name of up to four words. @internal */
const STREET_NAME = String.raw`${NAME_LINK}{0,3}\p{Lu}[\p{L}'-]*(?:\s${NAME_LINK}{0,3}\p{Lu}[\p{L}'-]*){0,3}`;

/**
 * House number first, then the street: `12 rue de la Paix`, `5 bis avenue Foch`.
 * @internal
 */
const NUMBER_FIRST_STREET_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\d])\d{1,4}(?:\s?(?:bis|ter))?,?\s+${STREET_TYPE}\s+${STREET_NAME}` +
    EU_TOWN,
  "gu",
);

/**
 * Street first, then the house number: `Calle Mayor 5`, `Via Roma 10`,
 * `Av. Paulista, 1578`, `Rua das Flores, nº 123`.
 * @internal
 */
const TYPE_FIRST_STREET_PATTERN = new RegExp(
  String.raw`(?<![\p{L}\d])${STREET_TYPE}\s+${STREET_NAME},?\s+(?:n[º°o.]\s?)?\d{1,5}[A-Za-z]?(?![\p{L}\d])` +
    EU_TOWN,
  "gu",
);

/**
 * UK postcode: e.g. SW1A 2AA, EC1A 1BB, W1A 0AX
 * @internal
 */
const UK_POSTCODE_PATTERN = /\b[A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2}\b/gi;

/**
 * PO Box pattern.
 * @internal
 */
const PO_BOX_PATTERN = /\bP\.?O\.?\s+Box\s+\d+\b/gi;

/**
 * Context-keyword prefixed addresses.
 * @internal
 */
const ADDRESS_CONTEXT_PATTERN =
  /(?:address(?:ed to)?|lives at|located at|shipped? to|mailing address|billing address|residence|resides at|home address|headquartered at|office address)\s*:?\s*([^\n,]{10,80})/gi;

/**
 * Detect physical addresses in `text`.
 *
 * @param text - The input string to scan.
 * @returns An array of {@link PiiMatch} objects with `category: "address"`.
 */
export function detectAddress(text: string): PiiMatch[] {
  const matches: PiiMatch[] = [];
  const seen = new Set<string>();

  function push(value: string, start: number, end: number, confidence: number): void {
    const key = `${String(start)}-${String(end)}`;
    if (seen.has(key)) return;
    seen.add(key);
    matches.push({ category: "address", value, start, end, confidence });
  }

  // US street addresses
  const usPattern = new RegExp(US_STREET_PATTERN.source, "gi");
  let m: RegExpExecArray | null;
  while ((m = usPattern.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.8);
  }

  // European and Brazilian streets. One that lies inside a street found
  // before it is not reported, and it replaces the shorter matches it contains.
  const streets: PiiMatch[] = [];
  for (const pattern of [
    SUFFIX_STREET_PATTERN,
    NUMBER_FIRST_STREET_PATTERN,
    TYPE_FIRST_STREET_PATTERN,
  ]) {
    pattern.lastIndex = 0;
    while ((m = pattern.exec(text)) !== null) {
      const start = m.index;
      const end = start + m[0].length;
      if (matches.some((found) => found.start <= start && end <= found.end)) continue;
      for (let index = matches.length - 1; index >= 0; index--) {
        const found = matches[index];
        /* v8 ignore next -- the index is within the array */
        if (found !== undefined && start <= found.start && found.end <= end) {
          matches.splice(index, 1);
        }
      }
      push(m[0], start, end, 0.8);
      streets.push({ category: "address", value: m[0], start, end, confidence: 0.8 });
    }
  }

  // UK postcodes
  const ukPattern = new RegExp(UK_POSTCODE_PATTERN.source, "gi");
  while ((m = ukPattern.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.78);
  }

  // PO Boxes
  const poPattern = new RegExp(PO_BOX_PATTERN.source, "gi");
  while ((m = poPattern.exec(text)) !== null) {
    push(m[0], m.index, m.index + m[0].length, 0.85);
  }

  // Context-keyword addresses
  const ctxPattern = new RegExp(ADDRESS_CONTEXT_PATTERN.source, "gi");
  while ((m = ctxPattern.exec(text)) !== null) {
    // ADDRESS_CONTEXT_PATTERN always captures group 1; fallback to m[0] is never needed.
    /* v8 ignore next */
    const captured = (m[1] ?? m[0]).trim();
    const start = text.indexOf(captured, m.index);
    const end = start + captured.length;
    // Part of a European street found whole: reporting it too would split the
    // street in two, since this match has the higher confidence.
    if (streets.some((street) => street.start <= start && end <= street.end)) continue;
    /* v8 ignore else -- the captured text lies inside the match, so indexOf always finds it */
    if (start !== -1) {
      push(captured, start, end, 0.82);
    }
  }

  return matches;
}
