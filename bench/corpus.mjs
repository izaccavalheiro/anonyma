/**
 * bench/corpus.mjs — deterministic synthetic corpus for the anonyma benchmark.
 *
 * Zero dependencies, plain Node ESM. Everything here is a pure function of
 * (size, density, seed): the same arguments always produce the same text, so a
 * baseline build and a later build are measured on byte-identical inputs.
 *
 * What is generated
 * -----------------
 * Realistic *shapes* of text, never real data:
 *   - log lines        `2026-03-14T09:15:22.123Z INFO auth login.ok user=... ip=...`
 *   - support tickets  short prose sentences with PII woven in
 *   - JSON records     one serialized JSON object per line (NDJSON)
 * plus a nested JSON object tree for anonymizeObject().
 *
 * Every planted PII value is clearly synthetic:
 *   - e-mail      *@example.com / example.org / example.net        (RFC 2606)
 *   - phone       NPA-555-01xx                                      (reserved for fiction)
 *   - IPv4        192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24     (RFC 5737)
 *   - IPv6        2001:db8::/32                                     (RFC 3849)
 *   - cards       public gateway test PANs (4111 1111 1111 1111 ...)
 *   - SSN         123-45-6789, 078-05-1120, 219-09-9999             (published specimens)
 *   - IBAN        registry specimen IBANs (GB82 WEST 1234 5698 7654 32 ...)
 *   - API key     the access key id from the AWS documentation
 *   - VIN         1M8GDM9AXKP042788                                 (check-digit textbook example)
 *   - tracking    1Z999AA10123456784                                (UPS documentation number)
 *   - names       Alice Example, Bob Sample, ... ; streets "123 Example Street"
 *   - the rest    obviously sequential placeholders (X12345678, 12-3456789, ...)
 *
 * PII density
 * -----------
 * `density` is "planted PII items per character". A feedback controller picks
 * how many items each line carries so the realised density converges on the
 * target (0 = none, 1/200 = sparse, 1/40 = dense). The *filler* between items
 * is curated so that the baseline detectors report nothing on it: with
 * density 0 the corpus yields zero matches (the harness verifies this and
 * prints a warning otherwise). That keeps the number of matches a controlled
 * variable. Real-world text additionally produces false positives; those are
 * a precision question and are deliberately not part of this corpus.
 *
 * The first planted item of every text is always an e-mail address, so that
 * "hasPII on a hit" is the same best case (first detector fires) at all sizes.
 *
 * All output is ASCII, so `text.length` equals the UTF-8 byte size and V8 uses
 * one-byte strings. `toTwoByte()` produces the two-byte variant for the probe
 * that measures the UTF-16 penalty.
 */

// ---------------------------------------------------------------------------
// Seeded PRNG
// ---------------------------------------------------------------------------

/**
 * mulberry32 — small, fast, well-distributed 32-bit PRNG.
 * @param {number} seed
 */
export function makeRng(seed) {
  let a = seed >>> 0;
  function next() {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  }
  return {
    next,
    /** integer in [0, n) */
    int: (n) => Math.floor(next() * n),
    /** integer in [lo, hi] */
    range: (lo, hi) => lo + Math.floor(next() * (hi - lo + 1)),
    pick: (arr) => arr[Math.floor(next() * arr.length)],
    chance: (p) => next() < p,
  };
}

/** FNV-1a over the string form of the parts — derives independent sub-seeds. */
export function seedFor(...parts) {
  const s = parts.join("|");
  let h = 0x811c9dc5;
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h >>> 0;
}

// ---------------------------------------------------------------------------
// Small formatting helpers
// ---------------------------------------------------------------------------

const pad = (n, width) => String(n).padStart(width, "0");
const digits = (r, n) => {
  let s = "";
  for (let i = 0; i < n; i++) s += String(r.int(10));
  return s;
};
const HEX_LETTERS = "abcdef";
/** 8-char id with strictly alternating letter/digit — matches no detector. */
const id8 = (r) => {
  let s = "";
  for (let i = 0; i < 4; i++) s += HEX_LETTERS[r.int(6)] + String(r.int(10));
  return s;
};
/** Fisher-Yates permutation of 0..n-1. */
const shuffled = (r, n) => {
  const a = Array.from({ length: n }, (_, i) => i);
  for (let i = n - 1; i > 0; i--) {
    const j = r.int(i + 1);
    const t = a[i];
    a[i] = a[j];
    a[j] = t;
  }
  return a;
};
const clockTs = (r) => `${pad(r.int(24), 2)}:${pad(r.int(60), 2)}:${pad(r.int(60), 2)}`;
const isoTs = (r) =>
  `2026-${pad(r.range(1, 12), 2)}-${pad(r.range(1, 28), 2)}T${pad(r.int(24), 2)}:${pad(r.int(60), 2)}:${pad(r.int(60), 2)}.${pad(r.int(1000), 3)}Z`;

// ---------------------------------------------------------------------------
// Synthetic PII catalogue
// ---------------------------------------------------------------------------

const FIRST = [
  "Alice",
  "Bob",
  "Carol",
  "Dave",
  "Erin",
  "Frank",
  "Grace",
  "Heidi",
  "Ivan",
  "Judy",
  "Mallory",
  "Olivia",
  "Peggy",
  "Rupert",
  "Sybil",
  "Trent",
  "Victor",
  "Walter",
];
const LAST = [
  "Example",
  "Sample",
  "Tester",
  "Placeholder",
  "Demo",
  "Fixture",
  "Specimen",
  "Synthetic",
  "Doe",
  "Roe",
];
const AREA = ["212", "312", "415", "503", "617", "702", "206", "305"];
const DOC_NETS = ["192.0.2.", "198.51.100.", "203.0.113."];
const TEST_CARDS = [
  "4111 1111 1111 1111",
  "4111-1111-1111-1111",
  "4111111111111111",
  "5555 5555 5555 4444",
  "5555555555554444",
  "4242 4242 4242 4242",
  "4012 8888 8888 1881",
  "3782 822463 10005",
  "378282246310005",
  "6011 1111 1111 1117",
  "5105 1051 0510 5100",
];
const SPECIMEN_SSN = ["123-45-6789", "078-05-1120", "219-09-9999"];
const SPECIMEN_IBAN = [
  "GB82 WEST 1234 5698 7654 32",
  "GB82WEST12345698765432",
  "DE89 3704 0044 0532 0130 00",
  "FR14 2004 1010 0505 0001 3M02 606",
  "NL91 ABNA 0417 1643 00",
  "ES91 2100 0418 4502 0005 1332",
  "CH93 0076 2011 6238 5295 7",
];
const MONTHS = [
  "January",
  "February",
  "March",
  "April",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];
const STREET_NAMES = ["Example", "Sample", "Placeholder", "Fixture", "Specimen", "Evergreen"];
const STREET_TYPES = ["Street", "Avenue", "Road", "Lane", "Terrace", "Court"];
const URL_SEGMENTS = ["orders", "invoices", "profile", "tickets", "docs"];
const HEX_WORDS = ["deadbeef", "c0ffee00", "0badf00d", "feedface"];
const PLATE_LETTERS = ["ABC", "XYZ", "TST", "DEM"];
const TITLES = ["Mr.", "Ms.", "Dr.", "Mrs."];

/**
 * One entry per PII category.
 *   gen(r)        -> the bare synthetic value
 *   log(v, r)     -> logfmt fragment            `key=value`
 *   prose(v, r)   -> short sentence
 *   json(v, r)    -> [key, stringValue] for an NDJSON field / object slot
 * `weight` is the relative prevalence in the mix (contact data dominates,
 * exotic identifiers are rare) — roughly what CRM/support/log data looks like.
 */
const CATALOGUE = [
  {
    cat: "email",
    weight: 16,
    gen: (r) =>
      `${r.pick(FIRST).toLowerCase()}.${r.pick(LAST).toLowerCase()}${r.range(10, 99)}@${r.pick(["example.com", "example.org", "example.net"])}`,
    log: (v) => `user=${v}`,
    prose: (v) => `Reach me at ${v}.`,
    json: (v) => ["email", v],
  },
  {
    cat: "phone",
    weight: 10,
    gen: (r) => {
      const a = r.pick(AREA);
      const n = `01${pad(r.int(100), 2)}`;
      switch (r.int(4)) {
        case 0:
          return `(${a}) 555-${n}`;
        case 1:
          return `${a}-555-${n}`;
        case 2:
          return `+1 ${a} 555 ${n}`;
        default:
          return `${a}.555.${n}`;
      }
    },
    log: (v) => `tel=${v}`,
    prose: (v) => `Call me on ${v}.`,
    json: (v) => ["phone", v],
  },
  {
    cat: "ipv4",
    weight: 10,
    gen: (r) => `${r.pick(DOC_NETS)}${r.range(1, 254)}`,
    log: (v) => `ip=${v}`,
    prose: (v) => `It came from ${v}.`,
    json: (v) => ["client_ip", v],
  },
  {
    cat: "url",
    weight: 8,
    gen: (r) =>
      r.chance(0.5)
        ? `https://example.com/${r.pick(URL_SEGMENTS)}/${r.range(1000, 99999)}`
        : `https://www.example.org/${r.pick(URL_SEGMENTS)}/${id8(r)}?ref=${r.range(10, 999)}`,
    log: (v) => `url=${v}`,
    prose: (v) => `See ${v} for details.`,
    json: (v) => ["link", v],
  },
  {
    cat: "name",
    weight: 8,
    gen: (r) => `${r.pick(FIRST)} ${r.pick(LAST)}`,
    log: (v, r) => `msg="approved by ${v}"`,
    prose: (v, r) =>
      r.chance(0.5)
        ? `I spoke with ${r.pick(TITLES)} ${v} today.`
        : `It was approved by ${v} already.`,
    json: (v, r) => ["contact", `${r.pick(TITLES)} ${v}`],
  },
  {
    cat: "credit-card",
    weight: 5,
    gen: (r) => r.pick(TEST_CARDS),
    log: (v) => `card=${v}`,
    prose: (v) => `My card ${v} was charged twice.`,
    json: (v) => ["card", v],
  },
  {
    cat: "date-of-birth",
    weight: 5,
    gen: (r) => {
      const y = r.range(1950, 2004);
      const m = r.range(1, 12);
      const d = r.range(1, 28);
      switch (r.int(4)) {
        case 0:
          return `${pad(m, 2)}/${pad(d, 2)}/${y}`;
        case 1:
          return `${r.pick(MONTHS)} ${d}, ${y}`;
        default:
          return `${y}-${pad(m, 2)}-${pad(d, 2)}`;
      }
    },
    log: (v) => `dob=${v}`,
    prose: (v) => `I was born on ${v}.`,
    json: (v) => ["birth_date", v],
  },
  {
    cat: "ssn",
    weight: 4,
    gen: (r) => r.pick(SPECIMEN_SSN),
    log: (v) => `ssn=${v}`,
    prose: (v) => `The SSN on file is ${v}.`,
    json: (v) => ["ssn", v],
  },
  {
    cat: "address",
    weight: 4,
    gen: (r) =>
      `${r.range(100, 9999)} ${r.pick(STREET_NAMES)} ${r.pick(STREET_TYPES)}${r.chance(0.3) ? ` Apt ${r.range(1, 40)}` : ""}`,
    log: (v) => `addr="${v}"`,
    prose: (v) => `Please send it to ${v}.`,
    json: (v) => ["street", v],
  },
  {
    cat: "ipv6",
    weight: 3,
    gen: (r) =>
      r.chance(0.5)
        ? `2001:db8:${digits(r, 4)}:${id8(r).slice(0, 4)}::${digits(r, 4)}`
        : `2001:0db8:${digits(r, 4)}:0000:0000:${id8(r).slice(0, 4)}:0370:${digits(r, 4)}`,
    log: (v) => `ip6=${v}`,
    prose: (v) => `The host is ${v} now.`,
    json: (v) => ["client_ip6", v],
  },
  {
    cat: "iban",
    weight: 3,
    gen: (r) => r.pick(SPECIMEN_IBAN),
    log: (v) => `iban=${v}`,
    prose: (v) => `Refund to ${v} please.`,
    json: (v) => ["iban", v],
  },
  {
    cat: "social-media",
    weight: 3,
    gen: (r) =>
      `@${r.pick(["example", "sample", "demo", "fixture"])}_${r.pick(["user", "dev", "ops"])}${r.int(10)}`,
    log: (v) => `handle=${v}`,
    prose: (v) => `Ping me as ${v} in chat.`,
    json: (v) => ["handle", v],
  },
  {
    cat: "api-key",
    weight: 2,
    // Assembled at run time: the literal would look like a credential to a secret scanner.
    gen: () => ["AKIA", "IOSFODNN7EXAMPLE"].join(""),
    log: (v) => `aws_key=${v}`,
    prose: (v) => `The key ${v} showed up in a log.`,
    json: (v) => ["access_key", v],
  },
  // --- rare identifiers (weight 1 each); most need a context keyword to be detected ---
  {
    cat: "passport",
    weight: 1,
    gen: (r) => `X${r.range(10000000, 99999999)}`,
    log: (v) => `passport=${v}`,
    prose: (v) => `My passport no: ${v}.`,
    json: (v) => ["passport", v],
  },
  {
    cat: "drivers-license",
    weight: 1,
    gen: (r) => `D${r.range(1000000, 9999999)}`,
    log: (v) => `dl=${v}`,
    prose: (v) => `My driving license: ${v}.`,
    json: (v) => ["dl", `DL# ${v}`],
  },
  {
    cat: "national-id",
    weight: 1,
    gen: (r) => `${digits(r, 3)}.${digits(r, 3)}.${digits(r, 3)}-${digits(r, 2)}`,
    log: (v) => `cpf=${v}`,
    prose: (v) => `My CPF is ${v}.`,
    json: (v) => ["cpf", v],
  },
  {
    cat: "bank-account",
    weight: 1,
    gen: (r) => `${digits(r, 2)}-${digits(r, 2)}-${digits(r, 2)}`,
    log: (v) => `sort_code=${v}`,
    prose: (v) => `The sort code is ${v}.`,
    json: (v) => ["sort_code", v],
  },
  {
    cat: "cryptocurrency",
    weight: 1,
    gen: (r) =>
      `0x${r.pick(HEX_WORDS)}${r.pick(HEX_WORDS)}${r.pick(HEX_WORDS)}${r.pick(HEX_WORDS)}${r.pick(HEX_WORDS)}`,
    log: (v) => `payout=${v}`,
    prose: (v) => `Payout goes to ${v}.`,
    json: (v) => ["payout", v],
  },
  {
    cat: "tax-id",
    weight: 1,
    gen: (r) => `${r.range(10, 98)}-${digits(r, 7)}`,
    log: (v) => `ein=${v}`,
    prose: (v) => `Our EIN is ${v}.`,
    json: (v) => ["ein", v],
  },
  {
    cat: "medical-record",
    weight: 1,
    gen: (r) => `QA${digits(r, 7)}`,
    log: (v) => `mrn=${v}`,
    prose: (v) => `Chart MRN: ${v}.`,
    json: (v) => ["mrn", `MRN ${v}`],
  },
  {
    cat: "health-insurance",
    weight: 1,
    gen: (r) => `HX${digits(r, 8)}`,
    log: (v) => `msg="member id ${v}"`,
    prose: (v) => `My member id ${v} is active.`,
    json: (v) => ["coverage", `member id ${v}`],
  },
  {
    cat: "prescription",
    weight: 1,
    gen: (r) => `${r.range(1000000, 9999999)}`,
    log: (v) => `rx=${v}`,
    prose: (v) => `Refill Rx# ${v} please.`,
    json: (v) => ["refill", `Rx# ${v}`],
  },
  {
    cat: "vin",
    weight: 1,
    gen: () => "1M8GDM9AXKP042788",
    log: (v) => `vin=${v}`,
    prose: (v) => `The VIN is ${v}.`,
    json: (v) => ["vin", v],
  },
  {
    cat: "license-plate",
    weight: 1,
    gen: (r) => `${r.pick(PLATE_LETTERS)}${digits(r, 4)}`,
    log: (v) => `plate=${v}`,
    prose: (v) => `The plate: ${v}.`,
    json: (v) => ["vehicle", `plate ${v}`],
  },
  {
    cat: "tracking-number",
    weight: 1,
    gen: () => "1Z999AA10123456784",
    log: (v) => `trk=${v}`,
    prose: (v) => `It ships as ${v}.`,
    json: (v) => ["carrier_ref", v],
  },
  {
    cat: "case-number",
    weight: 1,
    gen: (r) => `${r.range(1, 9)}:${r.range(20, 25)}-cv-${digits(r, 5)}`,
    log: (v) => `matter=${v}`,
    prose: (v) => `It is filed as ${v}.`,
    json: (v) => ["matter", v],
  },
  {
    cat: "company-registration",
    weight: 1,
    gen: (r) => `0${digits(r, 7)}`,
    log: (v) => `msg="company number ${v}"`,
    prose: (v) => `Our company number ${v} is unchanged.`,
    json: (v) => ["org", `company number ${v}`],
  },
];

const TOTAL_WEIGHT = CATALOGUE.reduce((s, e) => s + e.weight, 0);
const EMAIL_ENTRY = CATALOGUE[0];

/** Categories the corpus plants, in catalogue order. */
export const PLANTED_CATEGORIES = CATALOGUE.map((e) => e.cat);

function pickEntry(r) {
  let x = r.next() * TOTAL_WEIGHT;
  for (const e of CATALOGUE) {
    x -= e.weight;
    if (x < 0) return e;
  }
  return CATALOGUE[CATALOGUE.length - 1];
}

// ---------------------------------------------------------------------------
// Filler (PII-free) vocabulary
// ---------------------------------------------------------------------------

const LEVELS = ["INFO", "INFO", "INFO", "DEBUG", "WARN", "ERROR"];
const SERVICES = [
  "auth",
  "billing",
  "gateway",
  "search",
  "notifier",
  "scheduler",
  "storage",
  "checkout",
  "profile",
  "reports",
];
const EVENTS = [
  "login.ok",
  "login.retry",
  "invoice.created",
  "session.refresh",
  "export.started",
  "export.finished",
  "webhook.retry",
  "cache.miss",
  "quota.check",
  "order.updated",
  "index.rebuilt",
  "job.queued",
];
const REGIONS = ["eu-west-1", "us-east-2", "ap-south-1"];
const ROUTES = ["orders", "invoices", "sessions", "exports"];
const ACTIONS = ["list", "detail", "sync"];
const STATUSES = [200, 200, 200, 201, 204, 302, 400, 404, 500, 503];

const LOG_FILLERS = [
  (r) => `req=${id8(r)}`,
  (r) => `status=${r.pick(STATUSES)}`,
  (r) => `dur_ms=${r.range(1, 2500)}`,
  (r) => `bytes=${r.range(100, 99999)}`,
  (r) => `attempt=${r.range(1, 5)}`,
  (r) => `shard=${r.int(64)}`,
  (r) => `region=${r.pick(REGIONS)}`,
  (r) => `route=/v2/${r.pick(ROUTES)}/${r.pick(ACTIONS)}`,
  (r) => `cache=${r.pick(["hit", "miss"])}`,
  (r) => `build=v${r.range(1, 4)}.${r.int(30)}.${r.int(10)}`,
];

const JSON_FILLERS = [
  (r) => `"req":"${id8(r)}"`,
  (r) => `"ms":${r.range(1, 2500)}`,
  (r) => `"ok":${r.chance(0.8) ? "true" : "false"}`,
  (r) => `"attempt":${r.range(1, 5)}`,
  (r) => `"region":"${r.pick(REGIONS)}"`,
  (r) => `"build":"v${r.range(1, 4)}.${r.int(30)}.${r.int(10)}"`,
  (r) => `"status":${r.pick(STATUSES)}`,
];

const SUBJECTS = [
  "the export job",
  "the dashboard",
  "our nightly sync",
  "the mobile app",
  "the invoice page",
  "the search index",
  "the report builder",
  "the webhook",
  "the checkout flow",
  "the settings screen",
  "the upload step",
  "the billing summary",
  "the notification digest",
  "the admin console",
  "the adapter",
  "the same solution",
];
const PREDICATES = [
  "stopped responding",
  "keeps timing out",
  "shows a blank screen",
  "returned an error",
  "finished without problems",
  "is slower than usual",
  "works again after a restart",
  "fails on the second attempt",
  "loads only half of the rows",
  "ignores the selected filters",
  "duplicates some entries",
  "looks fine on our side",
  "needs a manual refresh",
  "was fixed in the latest build",
  "adds a tiny delay",
];
const TAILS = [
  "since the last update",
  "after the maintenance window",
  "when filters are applied",
  "during peak hours",
  "on the staging environment",
  "for most of our team",
  "in the afternoon",
  "whenever two people edit at once",
  "after switching browsers",
  "even with a clean profile",
  "according to the status page",
  "as described in the earlier thread",
];
const STANDALONE = [
  "Thanks for looking into this.",
  "We tried clearing the cache and restarting twice.",
  "Nothing changed in our setup recently.",
  "Let me know if more details would help.",
  "This blocks the monthly close for the finance group.",
  "A colleague sees the same behaviour on another laptop.",
  "It happened 3 times this week.",
  "The page shows error 502 after about 15 seconds.",
];

function fillerSentence(r) {
  if (r.chance(0.3)) return r.pick(STANDALONE);
  const s = `${r.pick(SUBJECTS)} ${r.pick(PREDICATES)} ${r.pick(TAILS)}.`;
  return s[0].toUpperCase() + s.slice(1);
}

// ---------------------------------------------------------------------------
// Density controller
// ---------------------------------------------------------------------------

/**
 * Keeps `items / chars` converging on `density` by deciding, unit by unit
 * (line or record), how many PII items the next unit should carry.
 */
function createController(density) {
  let chars = 0;
  let items = 0;
  return {
    get chars() {
      return chars;
    },
    get items() {
      return items;
    },
    /**
     * @param r        rng (randomised rounding avoids periodic patterns)
     * @param base     fixed overhead of the unit in chars
     * @param perItem  estimated chars one planted item adds
     * @param maxK     most items the unit can hold
     */
    want(r, base, perItem, maxK) {
      if (density <= 0) return 0;
      const denom = Math.max(0.15, 1 - density * perItem);
      const kStar = (density * (chars + base) - items) / denom;
      if (kStar <= 0) return 0;
      const lo = Math.floor(kStar);
      return Math.min(maxK, lo + (r.next() < kStar - lo ? 1 : 0));
    },
    /** Length the unit should reach so that density stays on target. */
    targetLen(k) {
      return density > 0 ? (items + k) / density - chars : 0;
    },
    commit(len, k) {
      chars += len;
      items += k;
    },
  };
}

// ---------------------------------------------------------------------------
// Line builders (one per flavour). Each returns the line WITHOUT newline.
// ---------------------------------------------------------------------------

function plant(r, k, forceEmailFirst, planted) {
  const out = [];
  for (let i = 0; i < k; i++) {
    const entry = forceEmailFirst && i === 0 ? EMAIL_ENTRY : pickEntry(r);
    out.push({ entry, value: entry.gen(r) });
    planted.push(entry.cat);
  }
  return out;
}

function logLine(r, picks, minLen, compact) {
  let line = compact
    ? `${clockTs(r)} ${r.pick(LEVELS)} ${r.pick(SERVICES)}`
    : `${isoTs(r)} ${r.pick(LEVELS)} ${r.pick(SERVICES)} ${r.pick(EVENTS)}`;
  for (const p of picks) line += ` ${p.entry.log(p.value, r)}`;
  // Each filler key at most once per line (lines may end up shorter than minLen).
  const order = shuffled(r, LOG_FILLERS.length);
  for (let i = 0; i < order.length && line.length < minLen; i++)
    line += ` ${LOG_FILLERS[order[i]](r)}`;
  return line;
}

function proseLine(r, picks, minLen) {
  const parts = [];
  if (picks.length === 0 || r.chance(0.5)) parts.push(fillerSentence(r));
  for (const p of picks) parts.push(p.entry.prose(p.value, r));
  let line = parts.join(" ");
  while (line.length < minLen) line += ` ${fillerSentence(r)}`;
  return line;
}

function jsonLine(r, picks, minLen) {
  const fields = [`"ts":"${isoTs(r)}"`];
  if (picks.length < 5)
    fields.push(`"level":"${r.pick(LEVELS).toLowerCase()}"`, `"svc":"${r.pick(SERVICES)}"`);
  let n = 0;
  for (const p of picks) {
    const [key, value] = p.entry.json(p.value, r);
    // Suffix repeated keys so the line stays valid JSON with unique keys.
    fields.push(`"${n === 0 ? key : `${key}_${n}`}":"${value}"`);
    n++;
  }
  let line = `{${fields.join(",")}`;
  const order = shuffled(r, JSON_FILLERS.length);
  for (let i = 0; i < order.length && line.length + 1 < minLen; i++)
    line += `,${JSON_FILLERS[order[i]](r)}`;
  return `${line}}`;
}

// base overhead / chars per planted item / max items — used by the controller
const FLAVOUR = {
  log: { base: 50, perItem: 26, maxK: 8, build: logLine },
  prose: { base: 0, perItem: 34, maxK: 6, build: proseLine },
  json: { base: 62, perItem: 29, maxK: 8, build: jsonLine },
};
const BLOCK_ORDER = ["log", "prose", "json"];

/**
 * Infinite, deterministic source of lines (each ends with "\n").
 *
 * @param {{ density: number, seed: number, flavour?: 'mixed'|'log'|'prose'|'json' }} opts
 */
export function createLineSource({ density, seed, flavour = "mixed" }) {
  const r = makeRng(seed);
  const ctl = createController(density);
  let blockIdx = -1;
  let blockLeft = 0;
  let first = true;

  function nextFlavour() {
    if (flavour !== "mixed") return flavour;
    if (blockLeft <= 0) {
      blockIdx = (blockIdx + 1) % BLOCK_ORDER.length;
      blockLeft = BLOCK_ORDER[blockIdx] === "log" ? r.range(4, 9) : r.range(2, 5);
    }
    blockLeft--;
    return BLOCK_ORDER[blockIdx];
  }

  return {
    /** @returns {{ line: string, cats: string[] }} */
    next() {
      const fl = FLAVOUR[nextFlavour()];
      let k = ctl.want(r, fl.base, fl.perItem, fl.maxK);
      if (first && density > 0 && k === 0) k = 1; // every PII-bearing text has >= 1 item
      const cats = [];
      const picks = plant(r, k, first && density > 0, cats);
      first = false;
      const typical = 80 + r.int(80);
      const minLen =
        density > 0 && k > 0 ? Math.min(230, Math.max(0, Math.floor(ctl.targetLen(k)))) : typical;
      const line = `${fl.build(r, picks, minLen, false)}\n`;
      ctl.commit(line.length, k);
      return { line, cats };
    },
  };
}

// ---------------------------------------------------------------------------
// Public: makeText()
// ---------------------------------------------------------------------------

/**
 * Build a text of exactly `size` characters (== bytes; ASCII only).
 *
 * @param {{ size: number, density: number, seed: number, flavour?: string }} opts
 * @returns {{ text: string, size: number, lines: number, planted: number, plantedByCategory: Record<string, number> }}
 */
export function makeText({ size, density, seed, flavour = "mixed" }) {
  const plantedByCategory = Object.create(null);
  let planted = 0;
  const note = (cats) => {
    for (const c of cats) {
      plantedByCategory[c] = (plantedByCategory[c] ?? 0) + 1;
      planted++;
    }
  };

  const parts = [];
  let len = 0;
  let lines = 0;

  if (size < 320) {
    // Too small for the regular line shapes: one compact log line.
    const r = makeRng(seedFor(seed, "compact", size));
    const want = density > 0 ? Math.max(1, Math.round(size * density)) : 0;
    let line = `${clockTs(r)} ${r.pick(LEVELS)} ${r.pick(SERVICES)}`;
    for (let i = 0; i < want; i++) {
      const entry = i === 0 ? EMAIL_ENTRY : pickEntry(r);
      const frag = ` ${entry.log(entry.gen(r), r)}`;
      if (line.length + frag.length > size - 1) continue; // does not fit — skip this item
      line += frag;
      note([entry.cat]);
    }
    parts.push(line);
    len = line.length;
    lines = 1;
  } else {
    const src = createLineSource({ density, seed, flavour });
    for (;;) {
      const { line, cats } = src.next();
      if (len + line.length > size) break;
      parts.push(line);
      len += line.length;
      lines++;
      note(cats);
    }
  }

  // Pad to the exact size with PII-free logfmt filler.
  const r = makeRng(seedFor(seed, "pad", size));
  if (size < 320) {
    let tail = "";
    while (len + tail.length < size - 1) tail += ` ${r.pick(LOG_FILLERS)(r)}`;
    parts.push(`${tail.slice(0, size - 1 - len)}\n`);
  } else if (len < size) {
    // Clock-time prefix on purpose: a truncated ISO timestamp ("2026-03-14")
    // would itself be reported as a date.
    let tail = `${clockTs(r)} INFO ${r.pick(SERVICES)} ${r.pick(EVENTS)}`;
    while (tail.length < size - len - 1) tail += ` ${r.pick(LOG_FILLERS)(r)}`;
    parts.push(`${tail.slice(0, size - len - 1)}\n`);
    lines++;
  }

  const text = parts.join("");
  if (text.length !== size) throw new Error(`corpus: built ${text.length} chars, wanted ${size}`);
  return { text, size, lines, planted, plantedByCategory };
}

/** Split into lines, each keeping its trailing newline (concatenation == input). */
export function splitLines(text) {
  return text.match(/[^\n]*\n|[^\n]+$/g) ?? [];
}

/** Split into fixed-size chunks the way a byte-oriented reader would. */
export function splitFixed(text, chunkSize) {
  const out = [];
  for (let i = 0; i < text.length; i += chunkSize) out.push(text.slice(i, i + chunkSize));
  return out;
}

/**
 * Two-byte (UTF-16) variant of an ASCII text with the same length and the
 * same matches: the first space becomes U+2003 (EM SPACE), which forces V8 to
 * store the whole string with 2 bytes per char. Real text gets there with a
 * single curly quote, emoji or non-Latin-1 letter.
 */
export function toTwoByte(text) {
  const i = text.indexOf(" ");
  if (i < 0) return `${text} `;
  return `${text.slice(0, i)} ${text.slice(i + 1)}`;
}

// ---------------------------------------------------------------------------
// Public: makeObject() — nested JSON payload for anonymizeObject()
// ---------------------------------------------------------------------------

const SLOTS = {
  email: (rec, v) => {
    rec.customer.contact.email = v;
  },
  phone: (rec, v) => {
    rec.customer.contact.phone = v;
  },
  ipv4: (rec, v) => {
    rec.request.clientIp = v;
  },
  name: (rec, v, r) => {
    rec.customer.displayName = `${r.pick(TITLES)} ${v}`;
  },
  address: (rec, v) => {
    rec.customer.street = v;
  },
  "date-of-birth": (rec, v) => {
    rec.customer.birthDate = v;
  },
  "credit-card": (rec, v) => {
    rec.payment = { ...(rec.payment ?? {}), card: v };
  },
  iban: (rec, v) => {
    rec.payment = { ...(rec.payment ?? {}), iban: v };
  },
  url: (rec, v) => {
    rec.request.referrer = v;
  },
};

function makeRecord(r, n, k, forceEmailFirst, note) {
  const rec = {
    id: `rec-${pad(n, 6)}`,
    createdAt: isoTs(r),
    status: r.pick(["open", "pending", "closed"]),
    customer: {
      ref: `cus-${id8(r)}`,
      locale: r.pick(["en-GB", "en-US", "pt-BR", "de-DE"]),
      contact: {},
    },
    request: {
      channel: r.pick(["web", "mobile", "api"]),
      agent: `client/${r.range(1, 4)}.${r.int(30)}.${r.int(10)}`,
      region: r.pick(REGIONS),
    },
    notes: [],
    tags: [r.pick(SERVICES), r.pick(["priority-low", "priority-high", "follow-up"])],
    metrics: { attempts: r.range(1, 5), durationMs: r.range(1, 2500), resolved: r.chance(0.5) },
  };
  const used = new Set();
  for (let i = 0; i < k; i++) {
    const entry = forceEmailFirst && i === 0 ? EMAIL_ENTRY : pickEntry(r);
    const value = entry.gen(r);
    const slot = SLOTS[entry.cat];
    if (slot && !used.has(entry.cat)) {
      slot(rec, value, r);
      used.add(entry.cat);
    } else {
      rec.notes.push(entry.prose(value, r));
    }
    note(entry.cat);
  }
  if (rec.notes.length === 0) rec.notes.push(fillerSentence(r));
  return rec;
}

/**
 * Build a nested, JSON-serializable object whose `JSON.stringify` length is
 * close to `size` (never above it).
 *
 * @param {{ size: number, density: number, seed: number }} opts
 * @returns {{ obj: object, bytes: number, records: number, strings: number, planted: number, plantedByCategory: Record<string, number> }}
 */
export function makeObject({ size, density, seed }) {
  const r = makeRng(seedFor(seed, "object"));
  const plantedByCategory = Object.create(null);
  let planted = 0;
  const note = (c) => {
    plantedByCategory[c] = (plantedByCategory[c] ?? 0) + 1;
    planted++;
  };

  let obj;
  if (size < 700) {
    // Smallest payloads: a minimal two-level object.
    const want = density > 0 ? Math.max(1, Math.round(size * density)) : 0;
    obj = { user: { ref: `cus-${id8(r)}` }, note: "ok" };
    for (let i = 0; i < want; i++) {
      const entry = i === 0 ? EMAIL_ENTRY : pickEntry(r);
      const [key, value] = entry.json(entry.gen(r), r);
      const next = { ...obj, user: { ...obj.user, [i === 0 ? key : `${key}_${i}`]: value } };
      if (JSON.stringify(next).length > size) continue;
      obj = next;
      note(entry.cat);
    }
    let noteText = fillerSentence(r);
    while (JSON.stringify({ ...obj, note: noteText }).length < size)
      noteText += ` ${fillerSentence(r)}`;
    const over = JSON.stringify({ ...obj, note: noteText }).length - size;
    obj = { ...obj, note: noteText.slice(0, Math.max(2, noteText.length - over)) };
  } else {
    const ctl = createController(density);
    obj = {
      export: { id: `exp-${id8(r)}`, generatedAt: isoTs(r), source: "crm", schema: "v2" },
      records: [],
    };
    let len = JSON.stringify(obj).length;
    ctl.commit(len, 0);
    let first = true;
    for (let n = 1; ; n++) {
      let k = ctl.want(r, 330, 42, 12);
      if (first && density > 0 && k === 0) k = 1;
      const cats = [];
      const rec = makeRecord(r, n, k, first && density > 0, (c) => cats.push(c));
      first = false;
      const recLen = JSON.stringify(rec).length + (obj.records.length > 0 ? 1 : 0);
      if (len + recLen > size) break;
      obj.records.push(rec);
      len += recLen;
      ctl.commit(recLen, k);
      for (const c of cats) note(c);
    }
    // Use the remaining room for a PII-free trailer string.
    const room = size - len - ',"trailer":""'.length;
    if (room > 0) {
      let t = "";
      while (t.length < room) t += `${fillerSentence(r)} `;
      obj.export = { ...obj.export, trailer: t.slice(0, room) };
    }
  }

  let strings = 0;
  (function walk(v) {
    if (typeof v === "string") strings++;
    else if (Array.isArray(v)) v.forEach(walk);
    else if (v && typeof v === "object") Object.values(v).forEach(walk);
  })(obj);

  return {
    obj,
    bytes: JSON.stringify(obj).length,
    records: Array.isArray(obj.records) ? obj.records.length : 0,
    strings,
    planted,
    plantedByCategory,
  };
}
