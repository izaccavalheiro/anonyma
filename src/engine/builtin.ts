/**
 * @module engine/builtin
 * @description The 27 built-in detectors as span detectors.
 *
 * Each export wraps the corresponding 1.x detector function and reports
 * exactly the same matches, so a pipeline built from them detects what
 * `detect()` detects. Every detector is a separate export: import only the
 * ones a pipeline needs and bundlers drop the rest.
 */

import { detectAddress } from "../detectors/address.js";
import { detectApiKey } from "../detectors/api-key.js";
import { detectBankAccount } from "../detectors/bank-account.js";
import { detectCaseNumber } from "../detectors/case-number.js";
import { detectCompanyRegistration } from "../detectors/company-registration.js";
import { detectCreditCard, detectCreditCardAggressive } from "../detectors/credit-card.js";
import { detectCryptocurrency } from "../detectors/cryptocurrency.js";
import { detectDateOfBirth } from "../detectors/date-of-birth.js";
import { detectDriversLicense } from "../detectors/drivers-license.js";
import { detectEmail, detectEmailAggressive } from "../detectors/email.js";
import { detectHealthInsurance } from "../detectors/health-insurance.js";
import { detectIban } from "../detectors/iban.js";
import { detectIpv4, detectIpv6 } from "../detectors/ip-address.js";
import { detectLicensePlate } from "../detectors/license-plate.js";
import { detectMedicalRecord } from "../detectors/medical-record.js";
import { detectName, detectNameAggressive } from "../detectors/name.js";
import { detectNationalId } from "../detectors/national-id.js";
import { detectPassport } from "../detectors/passport.js";
import { detectPhone, detectPhoneAggressive } from "../detectors/phone.js";
import { detectPrescription } from "../detectors/prescription.js";
import { detectSocialMedia } from "../detectors/social-media.js";
import { detectSsn, detectSsnAggressive } from "../detectors/ssn.js";
import { detectTaxId } from "../detectors/tax-id.js";
import { detectTrackingNumber } from "../detectors/tracking-number.js";
import { detectUrl } from "../detectors/url.js";
import { detectVin, detectVinAggressive } from "../detectors/vin.js";
import type { PiiCategory } from "../types.js";
import { fromLegacyDetector } from "./detector.js";
import type { SpanDetector } from "./types.js";

// ---------------------------------------------------------------------------
// Prefilters
// ---------------------------------------------------------------------------

let lastDigitText: string | undefined;
let lastDigitResult = false;

/**
 * `true` when the text contains an ASCII digit. Several detectors can only
 * match text with digits, so the answer for the most recent text is kept.
 */
function hasDigit(text: string): boolean {
  if (text !== lastDigitText) {
    lastDigitText = text;
    lastDigitResult = /\d/.test(text);
  }
  return lastDigitResult;
}

const hasAt = (text: string): boolean => text.includes("@");
const hasDot = (text: string): boolean => text.includes(".") && hasDigit(text);
const hasColon = (text: string): boolean => text.includes(":");
const hasScheme = (text: string): boolean => text.includes("://");

// ---------------------------------------------------------------------------
// Standard detectors
// ---------------------------------------------------------------------------

/** Email addresses. */
export const legacyEmailDetector: SpanDetector = fromLegacyDetector("email", detectEmail, {
  prefilter: hasAt,
});
/** Phone numbers. */
export const phoneDetector: SpanDetector = fromLegacyDetector("phone", detectPhone, {
  prefilter: hasDigit,
});
/** US Social Security Numbers. */
export const legacySsnDetector: SpanDetector = fromLegacyDetector("ssn", detectSsn, {
  prefilter: hasDigit,
  maxMatchLength: 11,
});
/** Payment card numbers. */
export const legacyCreditCardDetector: SpanDetector = fromLegacyDetector(
  "credit-card",
  detectCreditCard,
  { prefilter: hasDigit, maxMatchLength: 40 },
);
/** IPv4 addresses. */
export const legacyIpv4Detector: SpanDetector = fromLegacyDetector("ipv4", detectIpv4, {
  prefilter: hasDot,
  maxMatchLength: 18,
});
/** IPv6 addresses. */
export const legacyIpv6Detector: SpanDetector = fromLegacyDetector("ipv6", detectIpv6, {
  prefilter: hasColon,
  maxMatchLength: 45,
});
/** URLs. */
export const urlDetector: SpanDetector = fromLegacyDetector("url", detectUrl, {
  prefilter: hasScheme,
});
/** International Bank Account Numbers. */
export const legacyIbanDetector: SpanDetector = fromLegacyDetector("iban", detectIban, {
  prefilter: hasDigit,
  maxMatchLength: 42,
});
/** Dates of birth. */
export const dateOfBirthDetector: SpanDetector = fromLegacyDetector(
  "date-of-birth",
  detectDateOfBirth,
  { prefilter: hasDigit },
);
/** Person names (heuristic). */
export const nameDetector: SpanDetector = fromLegacyDetector("name", detectName);
/** Postal addresses. */
export const addressDetector: SpanDetector = fromLegacyDetector("address", detectAddress);
/** Passport numbers. */
export const passportDetector: SpanDetector = fromLegacyDetector("passport", detectPassport);
/** Driver's licence numbers. */
export const driversLicenseDetector: SpanDetector = fromLegacyDetector(
  "drivers-license",
  detectDriversLicense,
);
/** National identification numbers. */
export const nationalIdDetector: SpanDetector = fromLegacyDetector("national-id", detectNationalId);
/** Bank account and routing numbers. */
export const bankAccountDetector: SpanDetector = fromLegacyDetector(
  "bank-account",
  detectBankAccount,
);
/** Cryptocurrency wallet addresses. */
export const cryptocurrencyDetector: SpanDetector = fromLegacyDetector(
  "cryptocurrency",
  detectCryptocurrency,
);
/** Tax identification numbers. */
export const taxIdDetector: SpanDetector = fromLegacyDetector("tax-id", detectTaxId);
/** Medical record numbers. */
export const medicalRecordDetector: SpanDetector = fromLegacyDetector(
  "medical-record",
  detectMedicalRecord,
);
/** Health insurance identifiers. */
export const healthInsuranceDetector: SpanDetector = fromLegacyDetector(
  "health-insurance",
  detectHealthInsurance,
);
/** Prescription numbers. */
export const prescriptionDetector: SpanDetector = fromLegacyDetector(
  "prescription",
  detectPrescription,
);
/** API keys and access tokens. */
export const apiKeyDetector: SpanDetector = fromLegacyDetector("api-key", detectApiKey);
/** Social media handles and identifiers. */
export const socialMediaDetector: SpanDetector = fromLegacyDetector(
  "social-media",
  detectSocialMedia,
);
/** Vehicle identification numbers. */
export const vinDetector: SpanDetector = fromLegacyDetector("vin", detectVin);
/** Vehicle licence plates. */
export const licensePlateDetector: SpanDetector = fromLegacyDetector(
  "license-plate",
  detectLicensePlate,
);
/** Shipment tracking numbers. */
export const trackingNumberDetector: SpanDetector = fromLegacyDetector(
  "tracking-number",
  detectTrackingNumber,
);
/** Court case numbers. */
export const caseNumberDetector: SpanDetector = fromLegacyDetector("case-number", detectCaseNumber);
/** Company registration numbers. */
export const companyRegistrationDetector: SpanDetector = fromLegacyDetector(
  "company-registration",
  detectCompanyRegistration,
);

// ---------------------------------------------------------------------------
// Aggressive variants
// ---------------------------------------------------------------------------

/** Email addresses, including obfuscated forms such as `user [at] example [dot] com`. */
export const legacyEmailAggressiveDetector: SpanDetector = fromLegacyDetector(
  "email",
  detectEmailAggressive,
);
/** Phone numbers, including seven-digit local numbers. */
export const phoneAggressiveDetector: SpanDetector = fromLegacyDetector(
  "phone",
  detectPhoneAggressive,
  { prefilter: hasDigit },
);
/** US Social Security Numbers, aggressive variant. */
export const legacySsnAggressiveDetector: SpanDetector = fromLegacyDetector(
  "ssn",
  detectSsnAggressive,
  { prefilter: hasDigit, maxMatchLength: 11 },
);
/** Payment card numbers, including masked forms such as `****-****-****-1234`. */
export const legacyCreditCardAggressiveDetector: SpanDetector = fromLegacyDetector(
  "credit-card",
  detectCreditCardAggressive,
  { prefilter: hasDigit, maxMatchLength: 40 },
);
/** Person names, aggressive variant. */
export const nameAggressiveDetector: SpanDetector = fromLegacyDetector(
  "name",
  detectNameAggressive,
);
/** Vehicle identification numbers without checksum validation. */
export const vinAggressiveDetector: SpanDetector = fromLegacyDetector("vin", detectVinAggressive);

// ---------------------------------------------------------------------------
// Registries
// ---------------------------------------------------------------------------

/**
 * Every built-in category, in the order the 1.x engine scans them.
 */
export const BUILTIN_CATEGORIES: readonly PiiCategory[] = Object.freeze([
  "email",
  "phone",
  "ssn",
  "credit-card",
  "ipv4",
  "ipv6",
  "url",
  "iban",
  "date-of-birth",
  "name",
  "address",
  "passport",
  "drivers-license",
  "national-id",
  "bank-account",
  "cryptocurrency",
  "tax-id",
  "medical-record",
  "health-insurance",
  "prescription",
  "api-key",
  "social-media",
  "vin",
  "license-plate",
  "tracking-number",
  "case-number",
  "company-registration",
] as const);

/**
 * Span detectors that reproduce the 1.x detectors exactly, keyed by category.
 *
 * @example
 * ```ts
 * import { createPipeline, LEGACY_DETECTORS, redactWith } from "anonyma/engine";
 *
 * const pipeline = createPipeline({
 *   detectors: Object.values(LEGACY_DETECTORS),
 *   replace: { fallback: redactWith() },
 *   overlap: "legacy",
 * });
 * ```
 */
export const LEGACY_DETECTORS: Readonly<Record<PiiCategory, SpanDetector>> = Object.freeze({
  email: legacyEmailDetector,
  phone: phoneDetector,
  ssn: legacySsnDetector,
  "credit-card": legacyCreditCardDetector,
  ipv4: legacyIpv4Detector,
  ipv6: legacyIpv6Detector,
  url: urlDetector,
  iban: legacyIbanDetector,
  "date-of-birth": dateOfBirthDetector,
  name: nameDetector,
  address: addressDetector,
  passport: passportDetector,
  "drivers-license": driversLicenseDetector,
  "national-id": nationalIdDetector,
  "bank-account": bankAccountDetector,
  cryptocurrency: cryptocurrencyDetector,
  "tax-id": taxIdDetector,
  "medical-record": medicalRecordDetector,
  "health-insurance": healthInsuranceDetector,
  prescription: prescriptionDetector,
  "api-key": apiKeyDetector,
  "social-media": socialMediaDetector,
  vin: vinDetector,
  "license-plate": licensePlateDetector,
  "tracking-number": trackingNumberDetector,
  "case-number": caseNumberDetector,
  "company-registration": companyRegistrationDetector,
});

/**
 * The aggressive counterpart of {@link LEGACY_DETECTORS}: categories that have
 * an aggressive 1.x variant use it, all others use the standard detector.
 */
export const LEGACY_AGGRESSIVE_DETECTORS: Readonly<Record<PiiCategory, SpanDetector>> =
  Object.freeze({
    ...LEGACY_DETECTORS,
    email: legacyEmailAggressiveDetector,
    phone: phoneAggressiveDetector,
    ssn: legacySsnAggressiveDetector,
    "credit-card": legacyCreditCardAggressiveDetector,
    name: nameAggressiveDetector,
    vin: vinAggressiveDetector,
  });
