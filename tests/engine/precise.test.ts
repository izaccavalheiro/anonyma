import { describe, expect, it } from "vitest";
import {
  bareSsnDetector,
  createPipeline,
  creditCardDetector,
  emailDetector,
  ibanDetector,
  ipv4Detector,
  ipv6Detector,
  maskedCardDetector,
  obfuscatedEmailDetector,
  redactWith,
  ssnDetector,
} from "../../src/engine/index.js";
import type { SpanDetector } from "../../src/engine/index.js";

function found(detector: SpanDetector, text: string): string[] {
  const out: string[] = [];
  if (detector.prefilter?.(text) === false) return out;
  detector.scan(text, (start, end) => out.push(text.slice(start, end)));
  return out;
}

describe("engine/precise", () => {
  describe("emailDetector", () => {
    it("finds plain, internationalised, punycode and embedded addresses with exact boundaries", () => {
      expect(found(emailDetector, "Write to <alice@example.com>, or 'bob@example.org'.")).toEqual([
        "alice@example.com",
        "bob@example.org",
      ]);
      expect(found(emailDetector, "josé.garcia@example.com")).toEqual(["josé.garcia@example.com"]);
      expect(found(emailDetector, "name@example.xn--p1ai")).toEqual(["name@example.xn--p1ai"]);
      expect(found(emailDetector, "user=quentin@example.org&x=1")).toEqual(["quentin@example.org"]);
      expect(found(emailDetector, "https://example.net/users/victor@example.org/profile")).toEqual([
        "victor@example.org",
      ]);
      expect(found(emailDetector, "alice@example.com_backup.zip alice@example.com2")).toEqual([
        "alice@example.com",
        "alice@example.com",
      ]);
      expect(found(emailDetector, "Contact:alice@example.com(work)")).toEqual([
        "alice@example.com",
      ]);
    });

    it("reports an address that follows a URL, a label or a shell command", () => {
      const cases: [string, string][] = [
        ['{"website":"https://acme.com","email":"john.smith@acme.com"}', "john.smith@acme.com"],
        ["Acme Corp,https://acme.com,john.smith@acme.com,active", "john.smith@acme.com"],
        ["?redirect_uri=https://app.example.com&login_hint=bob@example.com", "bob@example.com"],
        ["References: jane.doe@example.com", "jane.doe@example.com"],
        ["References:\njane.doe@example.com (former manager)", "jane.doe@example.com"],
        ["Email:.alice@example.com", "alice@example.com"],
        ["contact al@example.com(work)", "al@example.com"],
        ["ssh alice.smith@example.com", "alice.smith@example.com"],
        ["scp report.pdf backup@files.example.net:/srv/in/", "backup@files.example.net"],
        ["'o'brien@example.com'", "o'brien@example.com"],
      ];
      for (const [text, address] of cases) {
        expect(found(emailDetector, text), text).toEqual([address]);
      }
    });

    it("scans a run of apostrophes in linear time", () => {
      const text = "o'".repeat(100_000) + "@";
      const started = performance.now();
      expect(found(emailDetector, text)).toEqual([]);
      expect(performance.now() - started).toBeLessThan(1500);
    });

    it("ignores look-alikes", () => {
      for (const text of [
        "logo@2x.png",
        "References: <CAFx7=abc@mail.gmail.com> <CAFx7=def@mail.gmail.com>",
        "systemd[1]: Started user@1000.service",
        "npm install my-lib@1.0.0-alpha.beta",
        "y = W@x.flatten()",
        "git@github.com:izaccavalheiro/anonyma.git",
        "https://admin:s3cret@db.example.com/console",
        "ssh://git@host.example.com/repo",
        "Message-ID: <CAFx7=abc123xyz@mail.gmail.com>",
        "no at sign here",
      ]) {
        expect(found(emailDetector, text), text).toEqual([]);
      }
    });
  });

  describe("obfuscatedEmailDetector", () => {
    it("finds an address written with spaces around the at sign", () => {
      expect(found(obfuscatedEmailDetector, "mail john.smith @ example.com today")).toEqual([
        "john.smith @ example.com",
      ]);
      expect(found(obfuscatedEmailDetector, "john.smith@ example.com")).toEqual([
        "john.smith@ example.com",
      ]);
    });

    it("finds bracketed, parenthesised, braced and defanged forms", () => {
      expect(found(obfuscatedEmailDetector, "mail user [at] example [dot] com now")).toEqual([
        "user [at] example [dot] com",
      ]);
      expect(found(obfuscatedEmailDetector, "user(at)example(dot)co(dot)uk")).toEqual([
        "user(at)example(dot)co(dot)uk",
      ]);
      expect(found(obfuscatedEmailDetector, "USER {AT} EXAMPLE {DOT} COM")).toHaveLength(1);
      expect(found(obfuscatedEmailDetector, "user[@]example[.]com")).toEqual([
        "user[@]example[.]com",
      ]);
      expect(found(obfuscatedEmailDetector, "look at example dot com")).toEqual([]);
    });
  });

  describe("ssnDetector", () => {
    it("finds an unseparated number when words sit between the label and the digits", () => {
      for (const text of [
        "My SSN is 123456789",
        "SSN number 123456789",
        "social security number is 078051120",
        "SSN of the applicant: 123456789",
        "SS# 123456789",
      ]) {
        expect(found(ssnDetector, text), text).toHaveLength(1);
      }
      // The label must be in the same sentence.
      expect(found(ssnDetector, "SSN verified. Order 123456789")).toEqual([]);
      expect(found(ssnDetector, "SSN on file\nOrder 123456789")).toEqual([]);
    });

    it("finds separated numbers, with any dash, dots or spaces", () => {
      expect(
        found(ssnDetector, "SSN 123-45-6789, 123 45 6789, 123.45.6789, SSN123-45-6789"),
      ).toHaveLength(4);
      expect(found(ssnDetector, "SSN: 123-45 6789 / 678 - 90 - 1234 / 123-45-\n6789")).toHaveLength(
        3,
      );
    });

    it("finds an unseparated number only after a label", () => {
      expect(found(ssnDetector, "SSN: 123456789")).toEqual(["123456789"]);
      expect(found(ssnDetector, "social security number 123456789.")).toEqual(["123456789"]);
      expect(found(ssnDetector, "order 123456789 shipped")).toEqual([]);
      expect(found(ssnDetector, "ssn 000456789")).toEqual([]);
    });

    it("ignores ZIP+4 codes, longer numbers and unassignable numbers", () => {
      for (const text of [
        "New York, NY 10001-1234",
        "Case 2024-318-22-9041",
        "000-45-6789",
        "666-45-6789",
        "900-45-6789",
        "123-00-6789",
        "123-45-0000",
        "123-45-67890",
        "no digits",
      ]) {
        expect(found(ssnDetector, text), text).toEqual([]);
      }
    });
  });

  describe("bareSsnDetector", () => {
    it("finds assignable nine-digit numbers with low confidence", () => {
      const confidences: number[] = [];
      bareSsnDetector.scan("id 123456789 and 000456789 and 1234567890", (_s, _e, c) =>
        confidences.push(c),
      );
      expect(confidences).toEqual([0.5]);
      expect(bareSsnDetector.prefilter?.("12345678")).toBe(false);
    });
  });

  describe("ibanDetector", () => {
    it("finds IBANs of countries that issue them outside the registry", () => {
      for (const iban of [
        "DZ58 0002 1000 0111 3000 0005 70",
        "MA64 0115 1900 0001 2050 0053 4921",
        "SN08 SN01 0015 2000 0485 0000 3035",
      ]) {
        expect(found(ibanDetector, `IBAN ${iban} please`), iban).toEqual([iban]);
      }
    });

    it("finds IBANs in print, electronic, hyphenated, lower-case and wrapped form", () => {
      expect(found(ibanDetector, "IBAN: BE68 5390 0754 7034 BIC: GKCCBEBB")).toEqual([
        "BE68 5390 0754 7034",
      ]);
      expect(found(ibanDetector, "DE89370400440532013000")).toEqual(["DE89370400440532013000"]);
      expect(found(ibanDetector, "DE89-3704-0044-0532-0130-00.")).toEqual([
        "DE89-3704-0044-0532-0130-00",
      ]);
      expect(found(ibanDetector, "iban: de89 3704 0044 0532 0130 00")).toEqual([
        "de89 3704 0044 0532 0130 00",
      ]);
      expect(found(ibanDetector, "DE89 3704 0044\n0532 0130 00")).toHaveLength(1);
      expect(found(ibanDetector, "IBAN_GB82WEST12345698765432")).toEqual([
        "GB82WEST12345698765432",
      ]);
    });

    it("ignores wrong lengths, unknown countries, bad checksums and embedded tokens", () => {
      for (const text of [
        "DE86 3704 0044 0532 0130",
        "XX68 ABCD 1234 5678",
        "DE89 3704 0044 0532 0130 01",
        "DE00 3704 0044 0532 0130 00",
        "DE100530573",
        "DE89370400440532013000X",
        "DE89 3704   0044 0532 0130 00",
        "DE89 3704",
      ]) {
        expect(found(ibanDetector, text), text).toEqual([]);
      }
    });
  });

  describe("ipv4Detector", () => {
    it("finds addresses after host names, dates, path segments and protocol names", () => {
      const cases: [string, string][] = [
        ["web-01 10.0.0.12 is down", "10.0.0.12"],
        ["srv-02 (10.0.0.7) unreachable", "10.0.0.7"],
        ["WEB-01 10.0.0.12 is down", "10.0.0.12"],
        ["us-east-1 23.45.67.89", "23.45.67.89"],
        ["12-Mar-2024 10.1.2.3 login ok", "10.1.2.3"],
        ["GET /geoip/203.0.113.57 HTTP/1.1", "203.0.113.57"],
        ["peer tcp/203.0.113.9:443", "203.0.113.9"],
        ["routing table 10.0.0.1", "10.0.0.1"],
        ["dhcp release 192.168.1.50", "192.168.1.50"],
        ["build 172.16.254.3 failed ping", "172.16.254.3"],
        ["host 192.168.1.10-server", "192.168.1.10"],
      ];
      for (const [text, address] of cases) {
        expect(found(ipv4Detector, text), text).toEqual([address]);
      }
    });

    it("still ignores versions, product tokens and references", () => {
      for (const text of [
        "Chrome/124.0.0.0 Safari/537.36",
        "nginx/1.25.3.1",
        "release 2.1.0.5",
        "build 1.2.3.4",
        "version 10.0.0.1",
        "Table 3.2.1.1",
        "ISO-27001 5.1.2.3",
        "section 10.1.2.3",
        "package 8.8.4.4-beta",
      ]) {
        expect(found(ipv4Detector, text), text).toEqual([]);
      }
    });

    it("finds addresses with ports, CIDR suffixes, URL hosts and zero padding", () => {
      expect(found(ipv4Detector, "client 203.0.113.57:443 via 10.0.0.0/8")).toEqual([
        "203.0.113.57",
        "10.0.0.0/8",
      ]);
      expect(found(ipv4Detector, "GET http://10.9.8.7/12 HTTP/1.1")).toEqual(["10.9.8.7"]);
      expect(found(ipv4Detector, "ip_10.0.0.5 and 192.168.001.010 and 1.1.1.1")).toEqual([
        "10.0.0.5",
        "192.168.001.010",
        "1.1.1.1",
      ]);
    });

    it("ignores versions, sections, grouped numbers, phones, netmasks and wrong arity", () => {
      for (const text of [
        "Mozilla/5.0 Chrome/124.0.0.0 Safari/537.36",
        "version 1.2.3.4",
        'AssemblyVersion("1.2.3.4")',
        "v1.2.3.4",
        "see section 1.2.3.4",
        "Table 2.1.3.1 lists",
        "ECMA-262 15.4.4.14",
        "libfoo 2.4.6.1-1ubuntu1",
        "app-1.2.3.4.jar",
        "1.2.3.4.5",
        "1.000.000.000 EUR",
        "Umsatz: 1.200.000.000",
        "Tel 02.123.45.67",
        "netmask 255.255.255.0",
        "listen 0.0.0.0:8080",
        "256.1.1.1",
        "no dots",
      ]) {
        expect(found(ipv4Detector, text), text).toEqual([]);
      }
    });
  });

  describe("ipv6Detector", () => {
    it("finds an address that is glued to a label", () => {
      const cases: [string, string][] = [
        ["Received: from mx ([IPv6:2001:db8::1])", "2001:db8::1"],
        ["IP:2001:db8::1", "2001:db8::1"],
        ["client:2001:db8:85a3::8a2e:370:7334", "2001:db8:85a3::8a2e:370:7334"],
        ["addr:fe80::1ff:fe23:4567:890a", "fe80::1ff:fe23:4567:890a"],
        ["eth0:2001:db8::1 up", "2001:db8::1"],
        ["[IPv6:::1]", "::1"],
      ];
      for (const [text, address] of cases) {
        expect(found(ipv6Detector, text), text).toEqual([address]);
      }
      expect(found(ipv6Detector, "T12:30:45.123 and 1:2:3:4:5:6:7:8:9")).toEqual([]);
    });

    it("finds full, compressed, link-local and IPv4-mapped addresses in full", () => {
      for (const address of [
        "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "2001:db8::1",
        "::1",
        "fe80::",
        "2001:db8:1::",
        "::ffff:192.0.2.128",
        "64:ff9b::192.0.2.33",
        "1:2:3:4:5:6:192.0.2.1",
      ]) {
        expect(found(ipv6Detector, `from ${address} now`), address).toEqual([address]);
      }
      expect(found(ipv6Detector, "address is 2001:db8::1.")).toEqual(["2001:db8::1"]);
      expect(found(ipv6Detector, "host: fe80::1: up")).toEqual(["fe80::1"]);
    });

    it("ignores times, MAC-style identifiers, scope operators and malformed addresses", () => {
      for (const text of [
        "at 12:30:45",
        "EUI-64 00:1A:2B:FF:FE:3C:4D:5E",
        "MAC 3C:22:FB:4A:9E:01",
        "std::cout << std::dec << value;",
        "let s = Add::add(a, b);",
        "dead::beef",
        "2001:db8::1::2",
        "1:2:3:4:5:6:7:8:9",
        "2001:db8::12345",
        "x2001:db8::1",
        "2001:db8::1x",
        "::",
        "a:b",
        "1:2:3:4:5:6:7::8",
        "1::192.0.2.1:5",
      ]) {
        expect(found(ipv6Detector, text), text).toEqual([]);
      }
    });
  });

  describe("creditCardDetector", () => {
    it("finds a card next to other digit groups", () => {
      const column = "Batch 2024\n4111 1111 1111 1111\n5500 0000 0000 0004\n4012 8888 8888 1881\n";
      expect(found(creditCardDetector, column)).toEqual([
        "4111 1111 1111 1111",
        "5500 0000 0000 0004",
        "4012 8888 8888 1881",
      ]);
      expect(found(creditCardDetector, "4111 1111 1111 1111\n123 Main Street")).toEqual([
        "4111 1111 1111 1111",
      ]);
      expect(found(creditCardDetector, "Card: 4111 1111 1111 1111 123")).toEqual([
        "4111 1111 1111 1111",
      ]);
      expect(found(creditCardDetector, "0000 4111 1111 1111 1111 5500 0000 0000 0004 end")).toEqual(
        ["4111 1111 1111 1111", "5500 0000 0000 0004"],
      );
      // The tail of one card and the head of the next never hide a card.
      expect(found(creditCardDetector, "1111\n5500 0000 0000 0004\n4012 8888 8888 1881")).toEqual([
        "5500 0000 0000 0004",
        "4012 8888 8888 1881",
      ]);
    });

    it("finds other groupings and networks outside the issuer table", () => {
      expect(found(creditCardDetector, "PAN 41111111 11111111")).toEqual(["41111111 11111111"]);
      expect(found(creditCardDetector, "PAN 622202 1234567890128")).toEqual([
        "622202 1234567890128",
      ]);
      for (const pan of [
        "9792 0303 9450 5556",
        "8600 1234 5678 9012",
        "9860 0123 4567 8903",
        "1041 2345 6789 010",
      ]) {
        expect(found(creditCardDetector, `card ${pan}`), pan).toEqual([pan]);
      }
      // Card-shaped, valid check digit, unknown network: reported with a low confidence.
      const hits: number[] = [];
      creditCardDetector.scan("ref 7000 0000 0000 0005", (_start, _end, confidence) => {
        hits.push(confidence);
      });
      expect(hits).toEqual([0.6]);
      expect(found(creditCardDetector, "0000 0000 0000 0000")).toEqual([]);
    });

    it("finds card numbers in every grouping and leaves neighbouring digits alone", () => {
      expect(found(creditCardDetector, "4111 1111 1111 1111 12/25")).toEqual([
        "4111 1111 1111 1111",
      ]);
      expect(found(creditCardDetector, "Amex 3782 822463 10005 1234")).toEqual([
        "3782 822463 10005",
      ]);
      expect(found(creditCardDetector, "Order 10023 4242 4242 4242 4242")).toEqual([
        "4242 4242 4242 4242",
      ]);
      expect(
        found(
          creditCardDetector,
          "4111.1111.1111.1111 / 5105-1051-0510-5100 / card_4111111111111111",
        ),
      ).toHaveLength(3);
      expect(
        found(creditCardDetector, "4222 2222 2222 2 and 36227206271667 and 6011111111111117"),
      ).toHaveLength(3);
      expect(
        found(
          creditCardDetector,
          "2223000048400011 3530111333300000 6200000000000005 2200000000000004",
        ),
      ).toHaveLength(4);
    });

    it("rates separated numbers above unseparated ones", () => {
      const confidences: number[] = [];
      creditCardDetector.scan("4111 1111 1111 1111 4111111111111111", (_s, _e, c) =>
        confidences.push(c),
      );
      expect(confidences).toEqual([0.97, 0.92]);
    });

    it("ignores numbers outside issuer ranges or failing Luhn", () => {
      for (const text of [
        "IMEI: 490154203237518",
        "0000000000000000",
        "4111111111111112",
        "tweet_id=1819595000000000185",
        "EAN 5901234123457",
        "Order 112-6492680-2384192",
        "12345678901234",
        "9999999999999995",
        "123",
      ]) {
        expect(found(creditCardDetector, text), text).toEqual([]);
      }
    });
  });

  describe("maskedCardDetector", () => {
    it("finds masked numbers", () => {
      for (const text of [
        "****-****-****-1234",
        "XXXX XXXX XXXX 1234",
        "xxxxxxxxxxxx1234",
        "•••• •••• •••• 1234",
      ]) {
        expect(found(maskedCardDetector, `card ${text}.`), text).toEqual([text]);
      }
      expect(found(maskedCardDetector, "plain text")).toEqual([]);
    });
  });

  it("covers every character of overlapping standard and aggressive hits", () => {
    const pipeline = createPipeline({
      detectors: [ssnDetector, bareSsnDetector, creditCardDetector, maskedCardDetector],
      replace: { fallback: redactWith() },
    });
    expect(pipeline.transform("SSN: 123456789 card ****-****-****-1234").text).toBe(
      "SSN: [REDACTED] card [REDACTED]",
    );
  });
});
