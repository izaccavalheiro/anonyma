/**
 * @module compliance/regulations
 * @description Regulation profiles: which categories of data each instrument
 * brings into scope, under which provision, and what protection the
 * transformed value must have.
 *
 * The profiles describe technical measures. They are not legal advice, and a
 * profile cannot make a system compliant on its own: every profile lists the
 * data elements its instrument names that this library cannot detect.
 */

import { ValidationError } from "../errors.js";
import type { StrategySpec } from "../engine/types.js";
import type { PiiCategory } from "../types.js";
import type {
  CategoryRule,
  LegalReference,
  ProtectionRequirement,
  RegulationId,
  RegulationProfile,
} from "./types.js";

function ref(citation: string, summary: string, url: string): LegalReference {
  return Object.freeze({ citation, summary, url });
}

function rules(
  categories: readonly PiiCategory[],
  references: readonly LegalReference[],
  requirement: ProtectionRequirement,
  recommended: StrategySpec,
  rationale: string,
): CategoryRule[] {
  return categories.map((category) =>
    Object.freeze({
      category,
      references,
      requirement: Object.freeze(requirement),
      recommended,
      rationale,
    }),
  );
}

const REDACT: StrategySpec = Object.freeze({ strategy: "redact" });

// ---------------------------------------------------------------------------
// GDPR
// ---------------------------------------------------------------------------

const GDPR_URL = "https://eur-lex.europa.eu/eli/reg/2016/679/oj";
const GDPR_PERSONAL_DATA = ref(
  "GDPR Art. 4(1)",
  "Personal data is any information relating to an identified or identifiable natural person, including a name, an identification number, location data and an online identifier.",
  GDPR_URL,
);
const GDPR_PSEUDONYMISATION = ref(
  "GDPR Art. 4(5)",
  "Pseudonymisation: the data can no longer be attributed to a data subject without additional information that is kept separately and protected.",
  GDPR_URL,
);
const GDPR_NATIONAL_ID = ref(
  "GDPR Art. 87",
  "Member States may set specific conditions for processing a national identification number.",
  GDPR_URL,
);
const GDPR_SPECIAL = ref(
  "GDPR Art. 9(1)",
  "Processing of special categories of personal data, including data concerning health, is prohibited unless an exception applies.",
  GDPR_URL,
);
const GDPR_ONLINE = ref(
  "GDPR Recital 30",
  "Online identifiers such as IP addresses and cookie identifiers may be used to identify natural persons.",
  GDPR_URL,
);
/** When an output is computed from the value, a separately kept secret must be involved. */
const KEYED_IF_DERIVED: ProtectionRequirement = { keyed: true };
const GDPR_DEFAULT: StrategySpec = Object.freeze({ strategy: "pseudonymize" });
const GDPR_RATIONALE =
  "A replacement that is computed from the value without a secret can be recomputed by anyone, so the data stays attributable and is not pseudonymised in the sense of Art. 4(5).";

const GDPR: RegulationProfile = {
  id: "gdpr",
  name: "General Data Protection Regulation",
  jurisdiction: "European Union / EEA",
  edition: "Regulation (EU) 2016/679",
  references: [
    ref(
      "GDPR Art. 5(1)(c)",
      "Data minimisation: adequate, relevant and limited to what is necessary.",
      GDPR_URL,
    ),
    ref(
      "GDPR Art. 5(1)(e)",
      "Storage limitation: identifiable form for no longer than necessary.",
      GDPR_URL,
    ),
    ref(
      "GDPR Art. 25(1)",
      "Data protection by design and by default, such as pseudonymisation.",
      GDPR_URL,
    ),
    ref(
      "GDPR Art. 32(1)(a)",
      "Security of processing includes the pseudonymisation and encryption of personal data.",
      GDPR_URL,
    ),
    ref(
      "GDPR Recital 26",
      "The principles of data protection do not apply to anonymous information.",
      GDPR_URL,
    ),
    GDPR_PSEUDONYMISATION,
  ],
  rules: [
    ...rules(
      ["name", "email", "phone", "address", "date-of-birth"],
      [GDPR_PERSONAL_DATA],
      KEYED_IF_DERIVED,
      GDPR_DEFAULT,
      GDPR_RATIONALE,
    ),
    ...rules(
      ["national-id", "ssn", "passport", "drivers-license", "tax-id"],
      [GDPR_PERSONAL_DATA, GDPR_NATIONAL_ID],
      KEYED_IF_DERIVED,
      GDPR_DEFAULT,
      GDPR_RATIONALE,
    ),
    ...rules(
      ["iban", "bank-account", "credit-card", "cryptocurrency"],
      [GDPR_PERSONAL_DATA],
      KEYED_IF_DERIVED,
      GDPR_DEFAULT,
      GDPR_RATIONALE,
    ),
    ...rules(
      ["ipv4", "ipv6", "url", "social-media"],
      [GDPR_PERSONAL_DATA, GDPR_ONLINE],
      KEYED_IF_DERIVED,
      GDPR_DEFAULT,
      GDPR_RATIONALE,
    ),
    ...rules(
      ["medical-record", "health-insurance", "prescription"],
      [GDPR_SPECIAL, GDPR_PERSONAL_DATA],
      KEYED_IF_DERIVED,
      GDPR_DEFAULT,
      "Identifiers of health records lead to data concerning health, a special category.",
    ),
  ],
  gaps: [
    {
      element: "Location data (coordinates, postal codes, city names)",
      reference: GDPR_PERSONAL_DATA,
      mitigation:
        "Add custom patterns for the formats in your data, or drop the fields that carry location.",
    },
    {
      element: "Device, advertising and cookie identifiers",
      reference: GDPR_ONLINE,
      mitigation: "Add custom patterns for the identifiers your systems emit.",
    },
    {
      element:
        "Special categories expressed in free text (health conditions, beliefs, union membership)",
      reference: GDPR_SPECIAL,
      mitigation:
        "Pattern matching cannot find these. Redact the fields that may contain them, by key.",
    },
    {
      element: "Names that are not introduced by a title, greeting or label",
      reference: GDPR_PERSONAL_DATA,
      mitigation: "Redact name fields by key; the name detector is a heuristic.",
    },
  ],
  auditTrail: ref(
    "GDPR Art. 30",
    "Controllers and processors maintain records of processing activities.",
    GDPR_URL,
  ),
  erasure: ref("GDPR Art. 17", "Right to erasure ('right to be forgotten').", GDPR_URL),
};

// ---------------------------------------------------------------------------
// LGPD
// ---------------------------------------------------------------------------

const LGPD_URL = "https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm";
const LGPD_PERSONAL_DATA = ref(
  "LGPD Art. 5, I",
  "Dado pessoal: information relating to an identified or identifiable natural person.",
  LGPD_URL,
);
const LGPD_SENSITIVE = ref(
  "LGPD Art. 5, II",
  "Dado pessoal sensível includes data concerning health, and genetic or biometric data linked to a natural person.",
  LGPD_URL,
);
const LGPD_RATIONALE =
  "Data is anonymised only if it can no longer be associated with an individual by reasonable technical means (Art. 5, XI and Art. 12); a keyless transformation of the value can be reversed.";

const LGPD: RegulationProfile = {
  id: "lgpd",
  name: "Lei Geral de Proteção de Dados Pessoais",
  jurisdiction: "Brazil",
  edition: "Lei nº 13.709/2018, as amended",
  references: [
    ref(
      "LGPD Art. 5, III",
      "Dado anonimizado: data whose subject cannot be identified by reasonable technical means.",
      LGPD_URL,
    ),
    ref(
      "LGPD Art. 5, XI",
      "Anonimização: means by which data loses the possibility of association with an individual.",
      LGPD_URL,
    ),
    ref(
      "LGPD Art. 6, III",
      "Necessidade: processing limited to the minimum necessary for its purposes.",
      LGPD_URL,
    ),
    ref(
      "LGPD Art. 12",
      "Anonymised data is not personal data unless the process can be reversed with reasonable effort.",
      LGPD_URL,
    ),
    ref(
      "LGPD Art. 13, § 4º",
      "Pseudonimização: association is only possible with additional information kept separately by the controller.",
      LGPD_URL,
    ),
    ref(
      "LGPD Art. 46",
      "Processing agents adopt technical and administrative security measures to protect personal data.",
      LGPD_URL,
    ),
  ],
  rules: [
    ...rules(
      [
        "name",
        "email",
        "phone",
        "address",
        "date-of-birth",
        "national-id",
        "tax-id",
        "passport",
        "drivers-license",
      ],
      [LGPD_PERSONAL_DATA],
      KEYED_IF_DERIVED,
      REDACT,
      LGPD_RATIONALE,
    ),
    ...rules(
      [
        "bank-account",
        "iban",
        "credit-card",
        "cryptocurrency",
        "ipv4",
        "ipv6",
        "url",
        "social-media",
        "license-plate",
      ],
      [LGPD_PERSONAL_DATA],
      KEYED_IF_DERIVED,
      REDACT,
      LGPD_RATIONALE,
    ),
    ...rules(
      ["medical-record", "health-insurance", "prescription"],
      [LGPD_SENSITIVE, LGPD_PERSONAL_DATA],
      KEYED_IF_DERIVED,
      REDACT,
      "Identifiers of health records lead to dado pessoal sensível.",
    ),
  ],
  gaps: [
    {
      element:
        "CPF without punctuation, CNPJ, RG, CNH, título de eleitor, PIS/PASEP and Cartão Nacional de Saúde numbers",
      reference: LGPD_PERSONAL_DATA,
      mitigation:
        "Only the punctuated CPF format is detected. Add custom patterns with the checksum validators for the others.",
    },
    {
      element:
        "Brazilian phone numbers in national format, CEP postal codes and addresses written in Portuguese",
      reference: LGPD_PERSONAL_DATA,
      mitigation: "Add custom patterns, or redact the fields that carry them by key.",
    },
    {
      element:
        "Sensitive data in free text (health, religion, political opinion, union membership)",
      reference: LGPD_SENSITIVE,
      mitigation:
        "Pattern matching cannot find these. Redact the fields that may contain them, by key.",
    },
  ],
  auditTrail: ref(
    "LGPD Art. 37",
    "Controller and operator keep a record of the processing operations they carry out.",
    LGPD_URL,
  ),
  erasure: ref(
    "LGPD Art. 18, IV and VI",
    "The data subject may obtain anonymisation, blocking or deletion of unnecessary or excessive data, and deletion of data processed with consent.",
    LGPD_URL,
  ),
};

// ---------------------------------------------------------------------------
// PIPEDA
// ---------------------------------------------------------------------------

const PIPEDA_URL = "https://laws-lois.justice.gc.ca/eng/acts/P-8.6/";
const PIPEDA_PERSONAL = ref(
  "PIPEDA s. 2(1)",
  "Personal information means information about an identifiable individual.",
  PIPEDA_URL,
);
const PIPEDA_SAFEGUARDS = ref(
  "PIPEDA Schedule 1, cl. 4.7",
  "Personal information is protected by security safeguards appropriate to its sensitivity; technological measures include passwords and encryption (cl. 4.7.3).",
  PIPEDA_URL,
);

const PIPEDA: RegulationProfile = {
  id: "pipeda",
  name: "Personal Information Protection and Electronic Documents Act",
  jurisdiction: "Canada (federal, private sector)",
  edition: "S.C. 2000, c. 5, as amended",
  references: [
    ref(
      "PIPEDA Schedule 1, cl. 4.4",
      "Limiting collection to what is necessary for the identified purposes.",
      PIPEDA_URL,
    ),
    PIPEDA_SAFEGUARDS,
    ref(
      "PIPEDA s. 10.1",
      "Breaches of security safeguards that create a real risk of significant harm are reported and notified.",
      PIPEDA_URL,
    ),
  ],
  rules: [
    ...rules(
      [
        "name",
        "email",
        "phone",
        "address",
        "date-of-birth",
        "national-id",
        "ssn",
        "passport",
        "drivers-license",
        "tax-id",
        "bank-account",
        "iban",
        "credit-card",
        "ipv4",
        "ipv6",
        "social-media",
      ],
      [PIPEDA_PERSONAL, PIPEDA_SAFEGUARDS],
      {},
      REDACT,
      "The Act prescribes no transformation; the safeguard has to match the sensitivity of the information.",
    ),
    ...rules(
      ["medical-record", "health-insurance", "prescription"],
      [PIPEDA_PERSONAL, PIPEDA_SAFEGUARDS],
      KEYED_IF_DERIVED,
      REDACT,
      "Health information is sensitive, so a replacement that anyone can recompute from the value is not an appropriate safeguard.",
    ),
  ],
  gaps: [
    {
      element:
        "Provincial health card numbers, postal codes, and bank transit and institution numbers",
      reference: PIPEDA_PERSONAL,
      mitigation: "Add custom patterns. The Social Insurance Number is detected as national-id.",
    },
    {
      element: "Names and addresses written in French",
      reference: PIPEDA_PERSONAL,
      mitigation:
        "Redact name and address fields by key; the detectors are tuned to English forms.",
    },
  ],
  auditTrail: ref(
    "PIPEDA s. 10.3",
    "Organizations keep a record of every breach of security safeguards.",
    PIPEDA_URL,
  ),
  erasure: ref(
    "PIPEDA Schedule 1, cl. 4.5.3",
    "Personal information that is no longer required should be destroyed, erased or made anonymous. This is a retention principle, not an individual right to erasure.",
    PIPEDA_URL,
  ),
};

// ---------------------------------------------------------------------------
// CCPA / CPRA
// ---------------------------------------------------------------------------

const CCPA_URL =
  "https://leginfo.legislature.ca.gov/faces/codes_displaySection.xhtml?lawCode=CIV&sectionNum=1798.140";
const CCPA_IDENTIFIERS = ref(
  "Cal. Civ. Code § 1798.140(v)(1)(A)",
  "Personal information includes identifiers such as a real name, postal address, online identifier, IP address, email address, social security number, driver's license number and passport number.",
  CCPA_URL,
);
const CCPA_RECORDS = ref(
  "Cal. Civ. Code § 1798.140(v)(1)(B)",
  "Personal information includes the categories of § 1798.80(e): telephone number, bank account and card numbers, medical information and health insurance information, among others.",
  CCPA_URL,
);
const CCPA_SENSITIVE = ref(
  "Cal. Civ. Code § 1798.140(ae)",
  "Sensitive personal information includes social security, driver's license, state identification card and passport numbers; account log-in and financial account or card numbers with their credentials; and health information.",
  CCPA_URL,
);
const CCPA_SENSITIVE_RATIONALE =
  "Pseudonymized information must not be attributable without separately kept information (§ 1798.140(aa)); a keyless transformation of sensitive personal information does not meet that.";

const CCPA: RegulationProfile = {
  id: "ccpa",
  name: "California Consumer Privacy Act, as amended by the California Privacy Rights Act",
  jurisdiction: "California, United States",
  edition: "Cal. Civ. Code §§ 1798.100–1798.199.100",
  references: [
    ref(
      "Cal. Civ. Code § 1798.100(e)",
      "A business implements reasonable security procedures and practices appropriate to the nature of the personal information.",
      CCPA_URL,
    ),
    ref(
      "Cal. Civ. Code § 1798.121",
      "A consumer may direct a business to limit its use of sensitive personal information.",
      CCPA_URL,
    ),
    ref(
      "Cal. Civ. Code § 1798.140(m)",
      "Deidentified information cannot reasonably be used to infer information about, or be linked to, a particular consumer.",
      CCPA_URL,
    ),
    ref(
      "Cal. Civ. Code § 1798.140(aa)",
      "Pseudonymization renders personal information no longer attributable without additional information that is kept separately.",
      CCPA_URL,
    ),
    ref(
      "Cal. Civ. Code § 1798.150",
      "Private right of action after a breach of nonencrypted and nonredacted personal information.",
      CCPA_URL,
    ),
  ],
  rules: [
    ...rules(
      ["name", "email", "address", "ipv4", "ipv6", "url", "social-media"],
      [CCPA_IDENTIFIERS],
      {},
      REDACT,
      "Redaction removes the identifier; the statute prescribes no particular transformation for non-sensitive identifiers.",
    ),
    ...rules(
      ["phone", "date-of-birth", "tax-id"],
      [CCPA_RECORDS],
      {},
      REDACT,
      "Covered through § 1798.80(e) or as information linkable to a consumer.",
    ),
    ...rules(
      ["ssn", "national-id", "passport", "drivers-license"],
      [CCPA_SENSITIVE, CCPA_IDENTIFIERS],
      KEYED_IF_DERIVED,
      REDACT,
      CCPA_SENSITIVE_RATIONALE,
    ),
    ...rules(
      ["bank-account", "credit-card", "api-key"],
      [CCPA_SENSITIVE, CCPA_RECORDS],
      KEYED_IF_DERIVED,
      REDACT,
      CCPA_SENSITIVE_RATIONALE,
    ),
    ...rules(
      ["medical-record", "health-insurance"],
      [CCPA_SENSITIVE, CCPA_RECORDS],
      KEYED_IF_DERIVED,
      REDACT,
      CCPA_SENSITIVE_RATIONALE,
    ),
  ],
  gaps: [
    {
      element: "Precise geolocation",
      reference: ref(
        "Cal. Civ. Code § 1798.140(w)",
        "Precise geolocation locates a consumer within a small geographic area.",
        CCPA_URL,
      ),
      mitigation: "Add custom patterns for coordinates, or drop the fields that carry them.",
    },
    {
      element: "Passwords, security codes and other account credentials",
      reference: CCPA_SENSITIVE,
      mitigation: "Redact credential fields by key. Only API-key shaped secrets are detected.",
    },
    {
      element: "Device, cookie and advertising identifiers",
      reference: ref(
        "Cal. Civ. Code § 1798.140(aj)",
        "A unique identifier is a persistent identifier that can recognise a consumer or a device over time.",
        CCPA_URL,
      ),
      mitigation: "Add custom patterns for the identifiers your systems emit.",
    },
    {
      element: "Biometric information, and inferences drawn about a consumer",
      reference: ref(
        "Cal. Civ. Code § 1798.140(c)",
        "Biometric information: physiological, biological or behavioural characteristics.",
        CCPA_URL,
      ),
      mitigation:
        "Pattern matching cannot find these. Redact the fields that may contain them, by key.",
    },
  ],
  erasure: ref(
    "Cal. Civ. Code § 1798.105",
    "A consumer may request deletion of personal information the business collected from the consumer.",
    CCPA_URL,
  ),
};

// ---------------------------------------------------------------------------
// HIPAA
// ---------------------------------------------------------------------------

const HIPAA_URL = "https://www.ecfr.gov/current/title-45/section-164.514";
const safeHarbor = (letter: string, summary: string): LegalReference =>
  ref(`45 CFR § 164.514(b)(2)(i)(${letter})`, summary, HIPAA_URL);
const HIPAA_REIDENTIFICATION = ref(
  "45 CFR § 164.514(c)",
  "A re-identification code must not be derived from or related to information about the individual, and the mechanism must not be disclosed.",
  HIPAA_URL,
);
/** Safe Harbor removes the identifier; a replacement code may not be derived from it. */
const REMOVED: ProtectionRequirement = {
  notDerived: true,
  maxRevealed: { leading: 0, trailing: 0 },
};
const HIPAA_RATIONALE =
  "Safe Harbor requires the identifier to be removed. A hash, keyed hash, ciphertext or partial mask of it is derived from information about the individual, which § 164.514(c) forbids for re-identification codes.";
const hipaa = (
  categories: readonly PiiCategory[],
  letter: string,
  summary: string,
): CategoryRule[] =>
  rules(
    categories,
    [safeHarbor(letter, summary), HIPAA_REIDENTIFICATION],
    REMOVED,
    REDACT,
    HIPAA_RATIONALE,
  );

const HIPAA: RegulationProfile = {
  id: "hipaa",
  name: "HIPAA Privacy Rule — de-identification by Safe Harbor",
  jurisdiction: "United States",
  edition: "45 CFR Part 164, Subpart E",
  references: [
    ref(
      "45 CFR § 164.514(a)",
      "Health information that does not identify an individual is not individually identifiable health information.",
      HIPAA_URL,
    ),
    ref(
      "45 CFR § 164.514(b)(1)",
      "Expert Determination: the alternative to Safe Harbor.",
      HIPAA_URL,
    ),
    ref(
      "45 CFR § 164.514(b)(2)(ii)",
      "The covered entity has no actual knowledge that the remaining information could identify the individual.",
      HIPAA_URL,
    ),
    HIPAA_REIDENTIFICATION,
  ],
  rules: [
    ...hipaa(["name"], "A", "Names."),
    ...hipaa(
      ["address"],
      "B",
      "All geographic subdivisions smaller than a State, including street address.",
    ),
    ...hipaa(
      ["date-of-birth"],
      "C",
      "All elements of dates (except year) directly related to an individual, including birth date.",
    ),
    ...hipaa(["phone"], "D", "Telephone numbers (and, under (E), fax numbers)."),
    ...hipaa(["email"], "F", "Electronic mail addresses."),
    ...hipaa(["ssn"], "G", "Social security numbers."),
    ...hipaa(["medical-record"], "H", "Medical record numbers."),
    ...hipaa(["health-insurance"], "I", "Health plan beneficiary numbers."),
    ...hipaa(["bank-account", "credit-card", "iban"], "J", "Account numbers."),
    ...hipaa(["drivers-license", "passport", "prescription"], "K", "Certificate/license numbers."),
    ...hipaa(
      ["vin", "license-plate"],
      "L",
      "Vehicle identifiers and serial numbers, including license plate numbers.",
    ),
    ...hipaa(["url"], "N", "Web Universal Resource Locators (URLs)."),
    ...hipaa(["ipv4", "ipv6"], "O", "Internet Protocol (IP) address numbers."),
    ...hipaa(
      ["national-id", "tax-id", "social-media"],
      "R",
      "Any other unique identifying number, characteristic, or code.",
    ),
  ],
  gaps: [
    {
      element: "City, county, precinct and ZIP code",
      reference: safeHarbor("B", "All geographic subdivisions smaller than a State."),
      mitigation:
        "Only street addresses are detected. Redact or generalise location fields by key.",
    },
    {
      element: "Admission, discharge and death dates, and ages over 89",
      reference: safeHarbor("C", "All elements of dates (except year), and all ages over 89."),
      mitigation:
        "Only dates that look like a date of birth are detected. Redact date and age fields by key.",
    },
    {
      element: "Device identifiers and serial numbers",
      reference: safeHarbor("M", "Device identifiers and serial numbers."),
      mitigation: "Add custom patterns for the device identifiers in your records.",
    },
    {
      element: "Biometric identifiers and full-face photographs",
      reference: safeHarbor("P", "Biometric identifiers; (Q) full-face photographic images."),
      mitigation: "Out of reach of text processing. Remove these attachments and fields.",
    },
    {
      element: "Names that are not introduced by a title, greeting or label",
      reference: safeHarbor("A", "Names."),
      mitigation: "Redact name fields by key; the name detector is a heuristic.",
    },
  ],
  auditTrail: ref(
    "45 CFR § 164.312(b)",
    "Audit controls: mechanisms that record and examine activity in systems that contain electronic protected health information.",
    "https://www.ecfr.gov/current/title-45/section-164.312",
  ),
};

// ---------------------------------------------------------------------------
// PCI DSS
// ---------------------------------------------------------------------------

const PCI_URL = "https://www.pcisecuritystandards.org/document_library/";
const PCI_DISPLAY = ref(
  "PCI DSS v4.0.1 Req. 3.4.1",
  "PAN is masked when displayed; the BIN and last four digits are the maximum number of digits to be displayed.",
  PCI_URL,
);
const PCI_STORAGE = ref(
  "PCI DSS v4.0.1 Req. 3.5.1",
  "PAN is rendered unreadable anywhere it is stored: one-way hashes of the entire PAN, truncation, index tokens, or strong cryptography.",
  PCI_URL,
);
const PCI_KEYED_HASH = ref(
  "PCI DSS v4.0.1 Req. 3.5.1.1",
  "Hashes used to render PAN unreadable are keyed cryptographic hashes of the entire PAN.",
  PCI_URL,
);
const PCI_SAD = ref(
  "PCI DSS v4.0.1 Req. 3.3.1",
  "Sensitive authentication data is not retained after authorization.",
  PCI_URL,
);

const PCI_ADJACENT = ref(
  "PCI DSS v4.0.1 Req. 3, account data",
  "Not account data; commonly stored next to it.",
  PCI_URL,
);

const PCI_DSS: RegulationProfile = {
  id: "pci-dss",
  name: "Payment Card Industry Data Security Standard",
  jurisdiction: "Global (contractual, card brands)",
  edition: "PCI DSS v4.0.1",
  references: [
    PCI_SAD,
    PCI_DISPLAY,
    PCI_STORAGE,
    PCI_KEYED_HASH,
    ref(
      "PCI DSS v4.0.1 Req. 3.7.5",
      "Key management covers the retirement, replacement or destruction of keys.",
      PCI_URL,
    ),
    ref(
      "PCI DSS v4.0.1 Req. 10.5.1",
      "Audit log history is retained for at least 12 months.",
      PCI_URL,
    ),
  ],
  rules: [
    ...rules(
      ["credit-card"],
      [PCI_DISPLAY, PCI_STORAGE, PCI_KEYED_HASH],
      { keyed: true, maxRevealed: { leading: 6, trailing: 4 } },
      { strategy: "mask", keepTrailing: 4 },
      "At most the BIN and the last four digits may stay visible, and a hash of the PAN has to be keyed.",
    ),
    ...rules(
      ["name"],
      [
        ref(
          "PCI DSS v4.0.1 Req. 3, account data",
          "Cardholder name is cardholder data and is protected when stored with the PAN.",
          PCI_URL,
        ),
      ],
      {},
      REDACT,
      "Cardholder name is part of cardholder data.",
    ),
    ...rules(
      ["bank-account"],
      [PCI_ADJACENT],
      {},
      { strategy: "mask", keepTrailing: 4 },
      "Outside the standard's definition of account data; masked like a PAN because it accompanies card data in payment records.",
    ),
    ...rules(
      ["address", "email", "phone"],
      [PCI_ADJACENT],
      {},
      REDACT,
      "Outside the standard's definition of account data; included because these fields accompany card data in payment records.",
    ),
  ],
  gaps: [
    {
      element:
        "Card verification codes, full track data and PINs or PIN blocks (sensitive authentication data)",
      reference: PCI_SAD,
      mitigation:
        "These must not be stored at all. Redact the fields that carry them by key; no detector finds them.",
    },
    {
      element: "Expiration date and service code",
      reference: ref(
        "PCI DSS v4.0.1 Req. 3, account data",
        "Expiration date and service code are cardholder data.",
        PCI_URL,
      ),
      mitigation: "Redact the fields that carry them by key.",
    },
  ],
  auditTrail: ref(
    "PCI DSS v4.0.1 Req. 10.2.1 and 10.3.2",
    "Audit logs are enabled for all system components and cardholder data, and protected from modification.",
    PCI_URL,
  ),
};

// ---------------------------------------------------------------------------
// Registry
// ---------------------------------------------------------------------------

function freezeProfile(profile: RegulationProfile): RegulationProfile {
  return Object.freeze({
    ...profile,
    references: Object.freeze([...profile.references]),
    rules: Object.freeze([...profile.rules]),
    gaps: Object.freeze(profile.gaps.map((gap) => Object.freeze({ ...gap }))),
  });
}

/**
 * Every regulation profile, keyed by identifier.
 *
 * @example
 * ```ts
 * import { REGULATIONS } from "anonyma/compliance";
 *
 * for (const rule of REGULATIONS.hipaa.rules) {
 *   console.log(rule.category, rule.references[0]?.citation);
 * }
 * ```
 */
export const REGULATIONS: Readonly<Record<RegulationId, RegulationProfile>> = Object.freeze({
  gdpr: freezeProfile(GDPR),
  lgpd: freezeProfile(LGPD),
  pipeda: freezeProfile(PIPEDA),
  ccpa: freezeProfile(CCPA),
  hipaa: freezeProfile(HIPAA),
  "pci-dss": freezeProfile(PCI_DSS),
});

/**
 * Whether `id` names a regulation profile.
 *
 * @example
 * ```ts
 * isRegulationId("hipaa"); // true
 * isRegulationId("sox");   // false
 * ```
 */
export function isRegulationId(id: unknown): id is RegulationId {
  return typeof id === "string" && Object.hasOwn(REGULATIONS, id);
}

/**
 * Get a regulation profile.
 *
 * @param id - The regulation identifier.
 * @returns The profile.
 * @throws {@link ValidationError} When `id` does not name a regulation profile.
 *
 * @example
 * ```ts
 * getRegulation("pci-dss").rules.find((rule) => rule.category === "credit-card")?.requirement;
 * // { keyed: true, maxRevealed: { leading: 6, trailing: 4 } }
 * ```
 */
export function getRegulation(id: RegulationId): RegulationProfile {
  if (!isRegulationId(id)) throw new ValidationError("regulation", "is not a known regulation");
  return REGULATIONS[id];
}

/**
 * One row of the compliance mapping matrix.
 */
export interface MatrixRow {
  /** The regulation. */
  readonly regulation: RegulationId;
  /** The category of data. */
  readonly category: PiiCategory;
  /** Citations that bring the category into scope. */
  readonly citations: readonly string[];
  /** The minimum protection, in words. */
  readonly requirement: string;
  /** The strategy the built-in preset applies. */
  readonly recommended: string;
}

function describeRequirement(requirement: ProtectionRequirement): string {
  const parts: string[] = [];
  if (requirement.irreversible === true) parts.push("irreversible");
  if (requirement.notDerived === true) parts.push("not derived from the value");
  if (requirement.keyed === true) parts.push("keyed if derived from the value");
  if (requirement.maxRevealed !== undefined) {
    const { leading, trailing } = requirement.maxRevealed;
    parts.push(
      leading + trailing === 0
        ? "nothing left visible"
        : `at most ${String(leading)} leading and ${String(trailing)} trailing characters visible`,
    );
  }
  return parts.length === 0 ? "clear value removed" : parts.join("; ");
}

/**
 * The compliance mapping matrix as data: one row per regulation and category.
 *
 * @returns The rows, ordered by regulation and then by category.
 *
 * @example
 * ```ts
 * complianceMatrix().filter((row) => row.category === "credit-card");
 * ```
 */
export function complianceMatrix(): MatrixRow[] {
  const rows: MatrixRow[] = [];
  for (const profile of Object.values(REGULATIONS)) {
    for (const rule of profile.rules) {
      const { strategy, ...optionsOf } = rule.recommended;
      const optionText = Object.entries(optionsOf)
        .map(([name, value]) => `${name}: ${String(value)}`)
        .join(", ");
      rows.push({
        regulation: profile.id,
        category: rule.category,
        citations: rule.references.map((reference) => reference.citation),
        requirement: describeRequirement(rule.requirement),
        recommended: optionText === "" ? strategy : `${strategy} (${optionText})`,
      });
    }
  }
  return rows;
}
