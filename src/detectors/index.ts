/**
 * @module detectors
 * @description Barrel export for all built-in PII detectors.
 *
 * Each detector is a pure function that accepts a string and returns an array of
 * {@link PiiMatch} objects. Import individual detectors for maximum tree-shaking,
 * or use the pre-assembled {@link DETECTOR_REGISTRY} for convenience.
 *
 * For aggressive (more permissive) detection, use {@link AGGRESSIVE_DETECTOR_REGISTRY}.
 *
 * @example
 * ```ts
 * import { detectEmail, detectPhone, DETECTOR_REGISTRY } from "anonyma/detectors";
 *
 * // Use a single detector:
 * const matches = detectEmail("hello@example.com");
 *
 * // Or scan for everything:
 * const allMatches = Object.values(DETECTOR_REGISTRY).flatMap((d) => d("some text"));
 * ```
 */

// --- Original detectors ---
export { detectEmail, detectEmailAggressive } from "./email.js";
export { detectPhone, detectPhoneAggressive } from "./phone.js";
export { detectSsn, detectSsnAggressive } from "./ssn.js";
export { detectCreditCard, detectCreditCardAggressive } from "./credit-card.js";
export { detectIpv4, detectIpv6 } from "./ip-address.js";
export { detectUrl } from "./url.js";
export { detectIban } from "./iban.js";
export { detectDateOfBirth } from "./date-of-birth.js";
export { detectName, detectNameAggressive } from "./name.js";

// --- Personal Information ---
export { detectAddress } from "./address.js";
export { detectPassport } from "./passport.js";
export { detectDriversLicense } from "./drivers-license.js";
export { detectNationalId } from "./national-id.js";

// --- Financial ---
export { detectBankAccount } from "./bank-account.js";
export { detectCryptocurrency } from "./cryptocurrency.js";
export { detectTaxId } from "./tax-id.js";

// --- Healthcare ---
export { detectMedicalRecord } from "./medical-record.js";
export { detectHealthInsurance } from "./health-insurance.js";
export { detectPrescription } from "./prescription.js";

// --- Digital Identity ---
export { detectApiKey } from "./api-key.js";
export { detectSocialMedia } from "./social-media.js";

// --- Vehicles & Transportation ---
export { detectVin, detectVinAggressive } from "./vin.js";
export { detectLicensePlate } from "./license-plate.js";
export { detectTrackingNumber } from "./tracking-number.js";

// --- Government & Legal ---
export { detectCaseNumber } from "./case-number.js";
export { detectCompanyRegistration } from "./company-registration.js";

import { detectEmail, detectEmailAggressive } from "./email.js";
import { detectPhone, detectPhoneAggressive } from "./phone.js";
import { detectSsn, detectSsnAggressive } from "./ssn.js";
import { detectCreditCard, detectCreditCardAggressive } from "./credit-card.js";
import { detectIpv4, detectIpv6 } from "./ip-address.js";
import { detectUrl } from "./url.js";
import { detectIban } from "./iban.js";
import { detectDateOfBirth } from "./date-of-birth.js";
import { detectName, detectNameAggressive } from "./name.js";
import { detectAddress } from "./address.js";
import { detectPassport } from "./passport.js";
import { detectDriversLicense } from "./drivers-license.js";
import { detectNationalId } from "./national-id.js";
import { detectBankAccount } from "./bank-account.js";
import { detectCryptocurrency } from "./cryptocurrency.js";
import { detectTaxId } from "./tax-id.js";
import { detectMedicalRecord } from "./medical-record.js";
import { detectHealthInsurance } from "./health-insurance.js";
import { detectPrescription } from "./prescription.js";
import { detectApiKey } from "./api-key.js";
import { detectSocialMedia } from "./social-media.js";
import { detectVin, detectVinAggressive } from "./vin.js";
import { detectLicensePlate } from "./license-plate.js";
import { detectTrackingNumber } from "./tracking-number.js";
import { detectCaseNumber } from "./case-number.js";
import { detectCompanyRegistration } from "./company-registration.js";

import type { DetectorRegistry } from "../types.js";

/**
 * A pre-assembled registry containing all built-in detectors, keyed by
 * {@link PiiCategory}.
 *
 * @example
 * ```ts
 * import { DETECTOR_REGISTRY } from "anonyma/detectors";
 *
 * const emailMatches = DETECTOR_REGISTRY.email("user@example.com");
 * ```
 */
export const DETECTOR_REGISTRY: DetectorRegistry = {
  // Original
  email: detectEmail,
  phone: detectPhone,
  ssn: detectSsn,
  "credit-card": detectCreditCard,
  ipv4: detectIpv4,
  ipv6: detectIpv6,
  url: detectUrl,
  iban: detectIban,
  "date-of-birth": detectDateOfBirth,
  name: detectName,
  // Personal Information
  address: detectAddress,
  passport: detectPassport,
  "drivers-license": detectDriversLicense,
  "national-id": detectNationalId,
  // Financial
  "bank-account": detectBankAccount,
  cryptocurrency: detectCryptocurrency,
  "tax-id": detectTaxId,
  // Healthcare
  "medical-record": detectMedicalRecord,
  "health-insurance": detectHealthInsurance,
  prescription: detectPrescription,
  // Digital Identity
  "api-key": detectApiKey,
  "social-media": detectSocialMedia,
  // Vehicles & Transportation
  vin: detectVin,
  "license-plate": detectLicensePlate,
  "tracking-number": detectTrackingNumber,
  // Government & Legal
  "case-number": detectCaseNumber,
  "company-registration": detectCompanyRegistration,
} as const;

/**
 * An alternative registry that uses expanded, more permissive patterns for each
 * detector. Enables detection of obfuscated or partial PII at the cost of a higher
 * false-positive rate.
 *
 * Use it by passing `aggressive: true` to {@link anonymize} / {@link createAnonymizer},
 * or directly via this registry for low-level usage.
 *
 * @example
 * ```ts
 * import { AGGRESSIVE_DETECTOR_REGISTRY } from "anonyma/detectors";
 *
 * const matches = AGGRESSIVE_DETECTOR_REGISTRY.email("user [at] example [dot] com");
 * ```
 */
export const AGGRESSIVE_DETECTOR_REGISTRY: DetectorRegistry = {
  // Original (aggressive variants where available)
  email: detectEmailAggressive,
  phone: detectPhoneAggressive,
  ssn: detectSsnAggressive,
  "credit-card": detectCreditCardAggressive,
  ipv4: detectIpv4,
  ipv6: detectIpv6,
  url: detectUrl,
  iban: detectIban,
  "date-of-birth": detectDateOfBirth,
  name: detectNameAggressive,
  // Personal Information
  address: detectAddress,
  passport: detectPassport,
  "drivers-license": detectDriversLicense,
  "national-id": detectNationalId,
  // Financial
  "bank-account": detectBankAccount,
  cryptocurrency: detectCryptocurrency,
  "tax-id": detectTaxId,
  // Healthcare
  "medical-record": detectMedicalRecord,
  "health-insurance": detectHealthInsurance,
  prescription: detectPrescription,
  // Digital Identity
  "api-key": detectApiKey,
  "social-media": detectSocialMedia,
  // Vehicles & Transportation
  vin: detectVinAggressive,
  "license-plate": detectLicensePlate,
  "tracking-number": detectTrackingNumber,
  // Government & Legal
  "case-number": detectCaseNumber,
  "company-registration": detectCompanyRegistration,
} as const;

