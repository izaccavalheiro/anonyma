# Security policy

anonyma handles personal data on behalf of the applications that use it, so
a defect here can become a data-protection incident somewhere else. Reports
are welcome and are treated as a priority.

## Supported versions

| Version | Supported                                    |
| ------- | -------------------------------------------- |
| 1.1.x   | yes (pre-releases under the `next` dist-tag) |
| 1.0.x   | security fixes only                          |
| < 1.0   | no                                           |

## Reporting a vulnerability

Report privately, through **GitHub private vulnerability reporting**: open the
repository's _Security_ tab and choose _Report a vulnerability_. Do not open a
public issue for a suspected vulnerability.

Please include:

- the version, the entry point (`anonyma`, `anonyma/engine`, …) and the
  runtime;
- the smallest input and configuration that show the problem, and what you
  expected instead;
- what an attacker gains: personal data left in the output, a token that
  resolves when it should not, a forged audit record, a denial of service.

**Use synthetic data only.** Never include real personal data, real
credentials or production logs in a report, an issue, a pull request or a
test. `alice@example.com`, the documentation IP ranges and the published test
card numbers are enough to reproduce anything.

## What counts

In scope, for example:

- personal data that a configured pipeline leaves in its output;
- a way to restore, forge or correlate tokens without the key or the session;
- a break of the audit chain that verification does not detect;
- key handling that weakens the documented cryptography;
- input that makes detection or restoration take time out of proportion to
  its size;
- anything that makes the package send data out of the process.

Detection is pattern-based. A value that no detector is documented to
recognise is a limit of the library and is tracked as an ordinary issue,
unless the documentation claims otherwise.

## What to expect

- An acknowledgement within 3 working days.
- An assessment, and a plan when the report is confirmed, within 10 working
  days.
- A fix released as a patch version, an advisory published with it, and
  credit to the reporter unless they prefer otherwise.

## How releases are protected

- The package has no runtime dependencies.
- Releases are built and published by GitHub Actions from a version tag, with
  an npm provenance attestation, a GitHub build attestation and a CycloneDX
  SBOM attached to the GitHub release.
  Verify a download with `npm audit signatures`, or with
  `gh attestation verify <tarball> --repo izaccavalheiro/anonyma`.
