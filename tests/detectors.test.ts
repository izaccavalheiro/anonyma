import { describe, it, expect } from "vitest";
import { detectEmail, detectEmailAggressive } from "../src/detectors/email.js";
import { detectPhone, detectPhoneAggressive } from "../src/detectors/phone.js";
import { detectSsn, detectSsnAggressive } from "../src/detectors/ssn.js";
import { detectCreditCard, detectCreditCardAggressive } from "../src/detectors/credit-card.js";
import { detectIpv4, detectIpv6 } from "../src/detectors/ip-address.js";
import { detectUrl } from "../src/detectors/url.js";
import { detectIban } from "../src/detectors/iban.js";
import { detectDateOfBirth } from "../src/detectors/date-of-birth.js";
import { detectName, detectNameAggressive } from "../src/detectors/name.js";
import { DETECTOR_REGISTRY, AGGRESSIVE_DETECTOR_REGISTRY } from "../src/detectors/index.js";

// ---------------------------------------------------------------------------
// Email
// ---------------------------------------------------------------------------
describe("detectEmail", () => {
  it("detects a simple email address", () => {
    const matches = detectEmail("Contact us at support@example.com.");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("support@example.com");
    expect(matches[0]?.category).toBe("email");
    expect(matches[0]?.confidence).toBeGreaterThan(0.9);
  });

  it("detects multiple email addresses", () => {
    const matches = detectEmail("From alice@a.com to bob@b.org");
    expect(matches).toHaveLength(2);
    expect(matches[0]?.value).toBe("alice@a.com");
    expect(matches[1]?.value).toBe("bob@b.org");
  });

  it("returns correct start/end indices", () => {
    const text = "Email: test@domain.io here";
    const matches = detectEmail(text);
    expect(matches).toHaveLength(1);
    const m = matches[0]!;
    expect(text.slice(m.start, m.end)).toBe(m.value);
  });

  it("does not false-positive on plain text", () => {
    expect(detectEmail("hello world no at signs here")).toHaveLength(0);
  });

  it("handles emails with subdomains and plus addressing", () => {
    const matches = detectEmail("user+tag@mail.example.co.uk");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("user+tag@mail.example.co.uk");
  });

  it("returns empty array for empty input", () => {
    expect(detectEmail("")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Phone
// ---------------------------------------------------------------------------
describe("detectPhone", () => {
  it("detects North American format with parentheses", () => {
    const matches = detectPhone("Call (555) 867-5309 now.");
    expect(matches).toHaveLength(1);
  });

  it("detects E.164 international format", () => {
    const matches = detectPhone("My number is +14155552671.");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.category).toBe("phone");
  });

  it("detects dotted format", () => {
    const matches = detectPhone("Reach me at 415.555.2671");
    expect(matches).toHaveLength(1);
  });

  it("does not match random digit sequences", () => {
    expect(detectPhone("No phone here: 12 34 56")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// SSN
// ---------------------------------------------------------------------------
describe("detectSsn", () => {
  it("detects hyphenated SSN", () => {
    const matches = detectSsn("SSN: 123-45-6789");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("123-45-6789");
    expect(matches[0]?.category).toBe("ssn");
  });

  it("detects spaceless SSN", () => {
    const matches = detectSsn("123456789");
    expect(matches).toHaveLength(1);
  });

  it("rejects SSNs starting with 000", () => {
    expect(detectSsn("000-12-3456")).toHaveLength(0);
  });

  it("rejects SSNs starting with 666", () => {
    expect(detectSsn("666-12-3456")).toHaveLength(0);
  });

  it("rejects SSNs starting with 9xx", () => {
    expect(detectSsn("900-12-3456")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// Credit Card
// ---------------------------------------------------------------------------
describe("detectCreditCard", () => {
  it("detects Visa test number (Luhn valid)", () => {
    const matches = detectCreditCard("Card: 4111 1111 1111 1111");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.category).toBe("credit-card");
    expect(matches[0]?.confidence).toBeGreaterThan(0.9);
  });

  it("detects Mastercard test number", () => {
    const matches = detectCreditCard("MC: 5500 0055 0055 0044");
    expect(matches).toHaveLength(1);
  });

  it("rejects Luhn-invalid sequences", () => {
    expect(detectCreditCard("1234 5678 9012 3456")).toHaveLength(0);
  });

  it("detects hyphen-separated card numbers", () => {
    const matches = detectCreditCard("4111-1111-1111-1111");
    expect(matches).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// IP Addresses
// ---------------------------------------------------------------------------
describe("detectIpv4", () => {
  it("detects a standard IPv4 address", () => {
    const matches = detectIpv4("Server: 192.168.1.100");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("192.168.1.100");
    expect(matches[0]?.category).toBe("ipv4");
  });

  it("detects IPv4 with CIDR notation", () => {
    const matches = detectIpv4("Subnet: 10.0.0.0/8");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("10.0.0.0/8");
  });

  it("does not match invalid octets like 999.0.0.1", () => {
    expect(detectIpv4("999.0.0.1")).toHaveLength(0);
  });

  it("detects loopback", () => {
    const matches = detectIpv4("Loopback: 127.0.0.1");
    expect(matches).toHaveLength(1);
  });
});

describe("detectIpv6", () => {
  it("detects a full IPv6 address", () => {
    const matches = detectIpv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.category).toBe("ipv6");
  });
});

// ---------------------------------------------------------------------------
// URL
// ---------------------------------------------------------------------------
describe("detectUrl", () => {
  it("detects an https URL", () => {
    const matches = detectUrl("Visit https://www.example.com");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.category).toBe("url");
  });

  it("detects URLs with paths and query strings", () => {
    const matches = detectUrl("Go to https://api.example.com/v1/users?id=42#section");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toContain("id=42");
  });

  it("does not match bare hostnames", () => {
    expect(detectUrl("example.com")).toHaveLength(0);
  });

  it("detects http URLs", () => {
    const matches = detectUrl("http://localhost:3000");
    expect(matches).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// IBAN
// ---------------------------------------------------------------------------
describe("detectIban", () => {
  it("detects a valid GB IBAN", () => {
    // GB82 WEST 1234 5698 7654 32 is a known valid IBAN.
    const matches = detectIban("IBAN: GB82WEST12345698765432");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.category).toBe("iban");
  });

  it("rejects an invalid IBAN (wrong check digits)", () => {
    expect(detectIban("GB00WEST12345698765432")).toHaveLength(0);
  });

  it("detects a space-grouped IBAN", () => {
    const matches = detectIban("Account: GB82 WEST 1234 5698 7654 32");
    expect(matches).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// Date-of-birth
// ---------------------------------------------------------------------------
describe("detectDateOfBirth", () => {
  it("detects ISO 8601 date", () => {
    const matches = detectDateOfBirth("DOB: 1990-04-15");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.category).toBe("date-of-birth");
    expect(matches[0]?.value).toBe("1990-04-15");
  });

  it("detects US MM/DD/YYYY format", () => {
    const matches = detectDateOfBirth("Born on 04/15/1990");
    expect(matches).toHaveLength(1);
  });

  it("detects long-form date: January 15, 1990", () => {
    const matches = detectDateOfBirth("Birthday: January 15, 1990");
    expect(matches).toHaveLength(1);
  });

  it("does not match future years beyond 20xx", () => {
    const matches = detectDateOfBirth("Year 2100 is the future");
    expect(matches).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// DETECTOR_REGISTRY
// ---------------------------------------------------------------------------
describe("DETECTOR_REGISTRY", () => {
  it("contains all expected categories", () => {
    const expected = [
      "email",
      "phone",
      "ssn",
      "credit-card",
      "ipv4",
      "ipv6",
      "url",
      "iban",
      "date-of-birth",
    ];
    for (const cat of expected) {
      expect(DETECTOR_REGISTRY).toHaveProperty(cat);
    }
  });

  it("each detector is callable and returns an array", () => {
    for (const detector of Object.values(DETECTOR_REGISTRY)) {
      expect(Array.isArray(detector("no pii here"))).toBe(true);
    }
  });

  it("includes the name detector", () => {
    const matches = DETECTOR_REGISTRY.name("Dear Alice Smith, your order is ready.");
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0]?.category).toBe("name");
  });
});

// ---------------------------------------------------------------------------
// detectName
// ---------------------------------------------------------------------------
describe("detectName", () => {
  it("detects a multi-word name after 'Dear'", () => {
    const matches = detectName("Dear Alice Smith, your account is ready.");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("Alice Smith");
    expect(matches[0]?.category).toBe("name");
    expect(matches[0]?.confidence).toBe(0.75);
  });

  it("detects a name after 'Hello'", () => {
    const matches = detectName("Hello John Doe, welcome back.");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("John Doe");
  });

  it("detects a name after 'Hi'", () => {
    const matches = detectName("Hi Jane Smith, please review.");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("Jane Smith");
  });

  it("detects a name after 'Greetings'", () => {
    const matches = detectName("Greetings Robert Johnson, welcome.");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("Robert Johnson");
  });

  it("detects a name after 'Hey there'", () => {
    const matches = detectName("Hey there Emily Clark, nice to meet you.");
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("Emily Clark");
  });

  it("detects a name after sentence-boundary greeting", () => {
    const text = "Thanks for your message. Dear Bob Williams, here is your response.";
    const matches = detectName(text);
    expect(matches).toHaveLength(1);
    expect(matches[0]?.value).toBe("Bob Williams");
  });

  it("returns correct start/end indices", () => {
    const text = "Dear Alice Smith, please respond.";
    const matches = detectName(text);
    expect(matches).toHaveLength(1);
    const m = matches[0]!;
    expect(text.slice(m.start, m.end)).toBe(m.value);
  });

  it("does not detect single capitalised words without greeting context", () => {
    // Single word capitalised names without greeting should be ignored in normal mode
    const matches = detectName("Alice went to the market.");
    expect(matches).toHaveLength(0);
  });

  it("does not false-positive on sentence-start capitalisation", () => {
    // Sentence that starts with a capitalised word but no greeting
    expect(detectName("The quick brown fox.")).toHaveLength(0);
  });

  it("returns empty array for empty input", () => {
    expect(detectName("")).toHaveLength(0);
  });

  it("detects names preceded by titles in normal mode (v2 enhancement)", () => {
    // As of v2, title-prefix detection is available in normal mode (not aggressive-only).
    const matches = detectName("Please contact Dr. Wilson for details.");
    expect(matches.length).toBeGreaterThanOrEqual(1);
    expect(matches.some((m) => m.value.includes("Wilson"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// detectNameAggressive
// ---------------------------------------------------------------------------
describe("detectNameAggressive (aggressive mode)", () => {
  it("detects names after title prefixes", () => {
    const matches = detectNameAggressive("Please see Dr. Smith for your appointment.");
    const nameMatch = matches.find((m) => m.value === "Smith");
    expect(nameMatch).toBeDefined();
    expect(nameMatch?.category).toBe("name");
    expect(nameMatch?.confidence).toBe(0.65);
  });

  it("detects names after 'Prof.' prefix", () => {
    const matches = detectNameAggressive("Contact Prof Johnson for the seminar.");
    expect(matches.some((m) => m.value.includes("Johnson"))).toBe(true);
  });

  it("still detects greeting-context names", () => {
    const matches = detectNameAggressive("Dear Alice Smith, welcome.");
    expect(matches.some((m) => m.value === "Alice Smith")).toBe(true);
  });

  it("has lower confidence than normal mode", () => {
    const normal = detectName("Dear Alice Smith, hi.");
    const aggressive = detectNameAggressive("Dear Alice Smith, hi.");
    const normalConf = normal[0]?.confidence ?? 1;
    const aggressiveConf = aggressive.find((m) => m.value === "Alice Smith")?.confidence ?? 1;
    expect(aggressiveConf).toBeLessThanOrEqual(normalConf);
  });
});

// ---------------------------------------------------------------------------
// detectEmailAggressive (aggressive mode)
// ---------------------------------------------------------------------------
describe("detectEmailAggressive (aggressive mode)", () => {
  it("detects standard emails (same as normal)", () => {
    const matches = detectEmailAggressive("Contact support@example.com for help.");
    expect(matches.some((m) => m.value === "support@example.com")).toBe(true);
  });

  it("detects [at] obfuscated emails", () => {
    const matches = detectEmailAggressive("Email user [at] example [dot] com for help.");
    expect(matches.length).toBeGreaterThan(0);
    expect(matches[0]?.category).toBe("email");
    expect(matches[0]?.confidence).toBe(0.75);
  });

  it("detects (at) obfuscated emails", () => {
    const matches = detectEmailAggressive("Send to alice(at)example(dot)com please.");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("does not double-report a standard email", () => {
    const matches = detectEmailAggressive("Contact support@example.com today.");
    const emailValues = matches.map((m) => m.value);
    const unique = new Set(emailValues);
    expect(unique.size).toBe(emailValues.length);
  });
});

// ---------------------------------------------------------------------------
// detectPhoneAggressive (aggressive mode)
// ---------------------------------------------------------------------------
describe("detectPhoneAggressive (aggressive mode)", () => {
  it("detects standard phone numbers (same as normal)", () => {
    const matches = detectPhoneAggressive("Call (555) 867-5309.");
    expect(matches.length).toBeGreaterThan(0);
  });

  it("detects 7-digit local formats", () => {
    const matches = detectPhoneAggressive("Call 555-1234 for info.");
    expect(matches.some((m) => m.value === "555-1234")).toBe(true);
    const sevenDigit = matches.find((m) => m.value === "555-1234");
    expect(sevenDigit?.confidence).toBe(0.7);
  });

  it("does not double-report a 10-digit number", () => {
    const matches = detectPhoneAggressive("555-867-5309");
    const starts = matches.map((m) => m.start);
    const unique = new Set(starts);
    expect(unique.size).toBe(starts.length);
  });
});

// ---------------------------------------------------------------------------
// detectSsnAggressive (aggressive mode)
// ---------------------------------------------------------------------------
describe("detectSsnAggressive (aggressive mode)", () => {
  it("detects hyphenated SSN (same as normal)", () => {
    const matches = detectSsnAggressive("SSN: 123-45-6789");
    expect(matches.some((m) => m.value === "123-45-6789")).toBe(true);
    expect(matches[0]?.confidence).toBe(0.95);
  });

  it("detects no-separator 9-digit SSN (normal pattern covers this case)", () => {
    // The normal SSN pattern already handles no-separator via optional [- ]? separators,
    // so detectSsnAggressive still finds the match (via the normal branch), with confidence 0.95.
    const matches = detectSsnAggressive("Found SSN 123456789 in file.");
    expect(matches.some((m) => m.value === "123456789")).toBe(true);
    // Confidence is 0.95 because the normal pattern catches it first
    const noSep = matches.find((m) => m.value === "123456789");
    expect(noSep?.confidence).toBe(0.95);
  });

  it("still rejects SSNs starting with 000", () => {
    expect(detectSsnAggressive("000-12-3456")).toHaveLength(0);
    expect(detectSsnAggressive("000123456")).toHaveLength(0);
  });
});

// ---------------------------------------------------------------------------
// detectCreditCardAggressive (aggressive mode)
// ---------------------------------------------------------------------------
describe("detectCreditCardAggressive (aggressive mode)", () => {
  it("detects standard Luhn-valid cards (same as normal)", () => {
    const matches = detectCreditCardAggressive("Card: 4111 1111 1111 1111");
    expect(matches.some((m) => m.value === "4111 1111 1111 1111")).toBe(true);
  });

  it("detects masked card format ****-****-****-1234", () => {
    const matches = detectCreditCardAggressive("Your card ****-****-****-1234 is on file.");
    expect(matches.some((m) => m.value === "****-****-****-1234")).toBe(true);
    const masked = matches.find((m) => m.value === "****-****-****-1234");
    expect(masked?.confidence).toBe(0.8);
  });

  it("detects masked card with spaces", () => {
    const matches = detectCreditCardAggressive("Card **** **** **** 5678");
    expect(matches.some((m) => m.value.includes("5678"))).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// AGGRESSIVE_DETECTOR_REGISTRY
// ---------------------------------------------------------------------------
describe("AGGRESSIVE_DETECTOR_REGISTRY", () => {
  const ALL_CATEGORIES = [
    "email", "phone", "ssn", "credit-card", "ipv4", "ipv6",
    "url", "iban", "date-of-birth", "name",
  ] as const;

  it("has a detector for every PII category", () => {
    for (const cat of ALL_CATEGORIES) {
      expect(AGGRESSIVE_DETECTOR_REGISTRY).toHaveProperty(cat);
    }
  });

  it("each aggressive detector is callable and returns an array", () => {
    for (const detector of Object.values(AGGRESSIVE_DETECTOR_REGISTRY)) {
      expect(Array.isArray(detector("no pii here"))).toBe(true);
    }
  });

  it("catches obfuscated email that normal registry misses", () => {
    const text = "Email user [at] example [dot] com to connect.";
    const normal = DETECTOR_REGISTRY.email(text);
    const aggressive = AGGRESSIVE_DETECTOR_REGISTRY.email(text);
    expect(normal.length).toBe(0);
    expect(aggressive.length).toBeGreaterThan(0);
  });
});
