---
title: Scrub logs and data files
sidebar_position: 1
description: Remove personal data from logs, CSV and JSON Lines of any size, and fail CI when a file has any.
---

The `anonyma` command reads files as streams, so a 10 GB log takes no more memory than a 10 KB one,
and it never sends anything anywhere.

```bash
npm install --global anonyma-cli anonyma
```

## Clean a file

```bash
anonyma scrub app.log -o app.safe.log
anonyma scrub customers.csv -o customers.safe.csv --preset lgpd
anonyma scrub events.jsonl.gz -o events.safe.jsonl.gz
```

- **Text** is scanned as a whole: a value split across lines or chunks is still found.
- **CSV** keeps its header, quoting and line endings; `--columns email,notes` limits the work to
  some columns.
- **JSON Lines** keeps structure, spacing and numbers exactly — a 20-digit ID comes out unchanged.

The output file appears only once it is complete; a run that fails leaves none behind.

## Check a file in CI

```bash
anonyma scan fixtures/customers.csv --fail-on-pii
```

```
fixtures/customers.csv: 3 values in 2 of 120 records
  email            2
  phone            1
```

`--list` prints one line per finding (`file:line:column: category`, never the value), and `--json`
a summary to feed into other tools. With `--fail-on-pii` the command exits with status 1 when
anything is found, which stops the job.

## Keep a record

```bash
ANONYMA_RECEIPT_KEY=… anonyma scrub export.csv -o export.safe.csv -p gdpr --receipt export.receipt.json
```

The receipt says when, with which presets, and how many values of each category were replaced, with
the SHA-256 of the output — signed, and without a single value. See
[Several regulations at once](several-regulations.md) for checking one.

Every option: [Command line](../packages/cli.md).
