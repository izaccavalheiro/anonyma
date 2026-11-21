# anonyma-cli

Scrub and scan files for personal data from the command line. Logs, JSON Lines and CSV of any size
are read as streams, so a 10 GB log takes no more memory than a 10 KB one, and nothing leaves the
machine: there is no network access, no telemetry and no dependency but
[`anonyma`](https://github.com/izaccavalheiro/anonyma).

```sh
npm install --global anonyma-cli anonyma

anonyma scrub customers.csv -o customers.safe.csv --preset lgpd
anonyma scan app.log.gz --fail-on-pii
```

## scrub

Replace the personal data of a file and write the result. The output file appears under its name
only once it is complete; a run that fails leaves none.

```sh
# Text, such as logs: every value found is replaced, also across chunk boundaries
anonyma scrub app.log -o app.safe.log

# CSV: cells are scrubbed, the header, quoting and line endings are kept
anonyma scrub people.csv -o people.safe.csv --preset gdpr

# Only some columns, by header name or number
anonyma scrub people.csv -o out.csv --columns email,notes

# JSON Lines: every string of every line, structure and numbers kept exactly
anonyma scrub events.jsonl -o events.safe.jsonl

# Pipes and compressed files
zcat app.log.gz | anonyma scrub -p hipaa | gzip > app.safe.log.gz
anonyma scrub app.log.gz -o app.safe.log.gz
```

```
$ anonyma scrub people.csv -o people.safe.csv -p lgpd
anonyma: people.csv: replaced 5 values (email 2, phone 2, national-id 1)
```

Several presets apply together (`-p lgpd,hipaa`): every category of every preset is detected, and
each gets the most protective of their strategies. `--strategy` applies one strategy to every
category instead: `redact` (the default, with `--label`), `mask`, `pseudonymize`, `synthesize`,
`generalize` or `hash`. The hash strategy reads its pepper from `ANONYMA_HASH_PEPPER`: without
one, the hash of a short value can be reversed by trying every value.

A policy document from `anonyma/compliance` describes everything at once, so that legal and
engineering review the same file:

```sh
anonyma scrub tickets.jsonl -o safe.jsonl --policy support-desk.policy.json
```

### Receipts

`--receipt` writes a signed receipt of the run: when, with which library version, presets and
policy, how many values of each category were replaced, and the SHA-256 of the output. It holds no
value from the data. The signature is an HMAC-SHA-256 under the key in `ANONYMA_RECEIPT_KEY`, so
whoever holds the key can show the receipt was not altered and names this output:

```sh
ANONYMA_RECEIPT_KEY=… anonyma scrub export.csv -o export.safe.csv -p gdpr --receipt export.receipt.json
```

```json
{
  "v": 1,
  "timestamp": "2026-11-21T10:00:00.000Z",
  "library": "anonyma@1.3.0",
  "presets": ["gdpr"],
  "stats": { "email": 1204, "phone": 311 },
  "total": 1515,
  "output": "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "alg": "HMAC-SHA-256",
  "signature": "…"
}
```

`createReceiptIssuer({ key }).verify(receipt, { output })` from `anonyma/audit` checks one. The
digest is of the uncompressed output.

## scan

Report personal data without changing anything: a summary, every finding, or JSON. Findings name
the line and column (text), the JSON Pointer (JSON Lines) or the record and column (CSV) — never
the value.

```
$ anonyma scan app.log
app.log: 3 values in 2 of 1,204 lines
  email            1
  ipv4             1
  credit-card      1

$ anonyma scan app.log --list
app.log:1:14: email
app.log:1:35: ipv4
app.log:3:6: credit-card

$ anonyma scan events.jsonl --list
events.jsonl:1: /user/email email

$ anonyma scan export.csv --json
{ "input": "export.csv", "format": "csv", "records": 1204, "recordsWithPii": 902, "total": 1515, "categories": { … } }
```

`--fail-on-pii` exits with status 1 when anything is found, to stop a CI job or a release that
would ship personal data:

```sh
anonyma scan seed/customers.csv --fail-on-pii
find logs -name '*.log' -exec anonyma scan {} --fail-on-pii --quiet --list \;
```

## Formats

| Format  | Chosen for                     | What is scanned                                                                                                        |
| ------- | ------------------------------ | ---------------------------------------------------------------------------------------------------------------------- |
| `txt`   | anything else                  | the text, also values that span lines (`scrub`); `scan` reads line by line                                             |
| `jsonl` | `.jsonl`, `.ndjson`            | every string, and integers of 12 digits or more; a line that is not JSON is processed as text, with a warning          |
| `csv`   | `.csv`, `.tsv` (tab-separated) | every cell, or the `--columns` asked for; the first row is a header unless `--no-header`; quoted fields may span lines |

`-f` chooses the format; a `.gz` suffix is looked through. Input is UTF-8.

## Options

```
anonyma scrub [input] [-o output] [options]
anonyma scan  [input] [options]

  -p, --preset <list>        Compliance presets, comma-separated
  -c, --categories <list>    Categories to detect (default: those of the presets, or all)
      --policy <file>        A policy document (JSON) from anonyma/compliance
      --min-confidence <n>   Leave detections below this confidence, 0 to 1
      --aggressive           Also use the permissive detector variants
      --legacy               Use the 1.x detectors instead of the validating ones
  -s, --strategy <name>      redact, mask, pseudonymize, synthesize, generalize, hash
      --label <text>         Replacement text of the redact strategy
      --receipt <file>       Write a signed receipt (key in ANONYMA_RECEIPT_KEY)
      --columns <list>       CSV: only these columns, by header name or 1-based number
      --no-header            CSV: the first row is data
  -d, --delimiter <char>     CSV: field delimiter (default "," or a tab for .tsv)
      --json                 scan: print the summary as JSON
      --list                 scan: print every finding
      --fail-on-pii          scan: exit with status 1 when personal data is found
  -o, --output <file>        scrub: where to write (default: standard output)
  -f, --format <format>      txt, jsonl or csv
  -q, --quiet                No summary on standard error
```

Exit status: 0 success, 1 personal data found (`scan --fail-on-pii`), 2 error.

## From a program

```ts
import { run } from "anonyma-cli";

process.exitCode = await run(["scan", "app.log", "--json"], {
  stdin: process.stdin,
  stdout: process.stdout,
  stderr: process.stderr,
  env: process.env,
});
```

`CsvReader` and `formatCsvRecord()` are the streaming CSV reader and writer the command uses: a
file read and written back with them is byte-for-byte the same.

## Requirements

Node.js 18.3 or later, and `anonyma` ^1.3.0 (a peer dependency).

## License

MIT
