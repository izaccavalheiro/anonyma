---
title: FAQ
sidebar_position: 7
---

## Does anonyma send my data anywhere?

No. The library has no network, file-system or process code, and no runtime dependencies; CI checks
both on every change. The [playground](/playground) runs the same code in your
browser and sends nothing you type to a server. This site uses Monoid analytics, which records page
views and clicks; its Content Security Policy allows no other connection.

## How accurate is detection?

It depends on the category. Formats with check digits (cards, IBANs, CPF, CNPJ, many national IDs)
are confirmed by the validating detectors, which leave look-alikes alone. Free-form data — names,
addresses — is found by patterns and context, and some will be missed; that is true of every
pattern-based tool. [Categories](reference/categories.md) says which is which. For names in free
text, consider an NER model in front of anonyma and pass its findings as a custom detector.

## Which strategy should I use?

Redact when nobody needs the value; mask when a human needs a hint (`****1111`); pseudonymize or
synthesize when the text must still read naturally; hash with a pepper when records must be joined
without the value; tokenize when the value must come back (an LLM round trip); encrypt when someone
authorised must recover it. See [Anonymization strategies](guide/strategies.md).

## Is pseudonymized data still personal data?

Under GDPR, usually yes: pseudonymised data that can be attributed with additional information stays
personal data (Recital 26). Keyed tokens and hashes reduce risk; they do not take data out of scope.
The [regulation profiles](reference/regulations.md) record what each regulation requires of a
strategy.

## Can I combine presets?

Yes: `preset: ["lgpd", "hipaa"]`. Each category gets the most protective strategy of the presets.
See [Several regulations at once](guides/several-regulations.md).

## Does it work with large files?

The [command line](packages/cli.md) streams text, CSV and JSON Lines in constant memory;
`createPipelineStream()` does the same in code.

## Is it stable? Which versions are supported?

`anonyma` is stable: it has followed semantic versioning since 1.0.0, and a change that breaks code
written for an earlier version needs a new major version. The latest minor version is supported,
and the one before it receives security fixes ([security policy](project/security.md)). The
companion packages are at 0.x, where a minor version may change the API, and the Python and Go
packages are alphas. The [releases page](project/releases.md) lists the latest version of each.

A fix can still change what you get back, when the library did not do what its documentation said.
The changelog puts such changes first in their release, and the [blog](/blog) says what to check
when you upgrade.

## Should I use anonyma, anonyma-parallel or anonyma-native?

Start with `anonyma`: it runs everywhere and does everything. Add
[`anonyma-parallel`](packages/parallel.md) when you process large batches on a machine with several
cores: it gives the same results and spreads the work over worker threads. Consider
[`anonyma-native`](packages/native.md) when you run Node.js on Linux, macOS or Windows, detect every
category or process batches, and need no custom detectors or plugins: it runs the Rust core, 2.4 to
7 times faster on the benchmark corpus. [Speed and batches](guides/speed-and-batches.md) measures
each.

## Why did anonyma add a Rust core?

For other languages, not for Node.js. Porting the detectors by hand to Python, Go or Java would run
them on different regular-expression engines, and the copies would drift. One core, checked against
the TypeScript library by a shared conformance suite, keeps every language on the same results. The
npm package keeps its TypeScript engine; [History and decisions](project/history.md) explains why.

## Is there a hosted version?

Not yet. Everything here runs where you run it.
